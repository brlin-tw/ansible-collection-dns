"""Optional real-BIND regression: set BIND_NAMED to a named executable."""

import copy
import os
import json
from pathlib import Path
import sys
import socket
import subprocess
import time

import dns.message
import dns.query
import dns.rcode
import pytest

from test_bind_reverse_updates import KEYS, OWNER, ZONE
from test_bind_zone_reconciler import _load_bind_zone_module


@pytest.mark.parametrize("policy_mode", ["rules", "local"])
def test_running_dynamic_zone_is_repaired_without_losing_ddns(tmp_path, policy_mode):
    executable = os.environ.get("BIND_NAMED")
    if not executable:
        pytest.skip("Set BIND_NAMED to run the isolated live-BIND test")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    builder = _load_bind_zone_module("builder").ZoneSpecBuilder()
    renderer = _load_bind_zone_module("renderer").ZoneFileRenderer()
    updater_class = _load_bind_zone_module("reverse_updates").ReverseRecordUpdater
    zone = copy.deepcopy(ZONE)
    if policy_mode == "local":
        zone["reverse_update_policy"] = {"mode": "local"}
    seed = dict(zone, hosts=[{"name": "ddns", "ip": "192.168.3.189"}])
    definitions = []
    for spec in builder.build([seed]).zone_files:
        if not spec.is_reverse:
            continue
        (tmp_path / spec.filename).write_text(renderer.render(spec, serial=1))
        policy = ('update-policy local;' if policy_mode == "local" else
                  'update-policy { grant ddns zonesub PTR; };')
        definitions.append(
            f'zone "{spec.origin}" {{ type primary; file "{spec.filename}"; {policy} }};'
        )
    config = tmp_path / "named.conf"
    session_key = tmp_path / "session.key"
    config.write_text(
        f'options {{ directory "{tmp_path}"; listen-on port {port} {{ 127.0.0.1; }}; '
        f'listen-on-v6 {{ none; }}; pid-file "{tmp_path}/named.pid"; '
        f'session-keyfile "{session_key}"; recursion no; dnssec-validation no; '
        'notify no; }; controls {}; '
        'key "ddns" { algorithm hmac-sha256; secret "dGVzdA=="; };\n'
        + '\n'.join(definitions)
    )
    with (tmp_path / "named.log").open("w+") as log:
        process = subprocess.Popen([executable, "-g", "-c", str(config), "-n", "1", "-U", "1"],
                                   stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 10
            while True:
                try:
                    response = dns.query.tcp(dns.message.make_query(OWNER, "PTR"),
                                             "127.0.0.1", port=port, timeout=0.2)
                    break
                except (OSError, dns.exception.Timeout):
                    if time.monotonic() > deadline or process.poll() is not None:
                        log.seek(0)
                        pytest.fail(log.read())
                    time.sleep(0.05)
            assert response.rcode() == dns.rcode.NXDOMAIN
            # Reproduce the old deployment: disk has the PTR; live BIND does not.
            for spec in builder.build([zone]).zone_files:
                if spec.is_reverse:
                    (tmp_path / spec.filename).write_text(renderer.render(spec, serial=2))
            assert updater_class(port=port, session_keyfile=str(session_key)).reconcile(
                [zone], KEYS, check_mode=True)
            response = dns.query.tcp(dns.message.make_query(OWNER, "PTR"),
                                     "127.0.0.1", port=port)
            assert response.rcode() == dns.rcode.NXDOMAIN
            assert updater_class(port=port, session_keyfile=str(session_key)).reconcile([zone], KEYS)
            assert not updater_class(port=port, session_keyfile=str(session_key)).reconcile([zone], KEYS)
            for owner, target in [(OWNER, "wireguard.infra.example."),
                                  ("189.3.168.192.in-addr.arpa.", "ddns.infra.example.")]:
                response = dns.query.tcp(dns.message.make_query(owner, "PTR"),
                                         "127.0.0.1", port=port)
                assert str(response.answer[0][0]) == target
            # Exercise value-dependent prerequisites when replacing an old PTR.
            zone["hosts"][0]["name"] = "vpn"
            # Exercise the Ansible module wrapper and argument serialization too.
            package = tmp_path / "collections" / "ansible_collections" / "bodsch"
            package.mkdir(parents=True)
            repo = Path(__file__).resolve().parents[2]
            (package / "dns").symlink_to(repo, target_is_directory=True)
            args = {"ANSIBLE_MODULE_ARGS": {
                "zones": [zone], "keys": KEYS, "port": port,
                "session_keyfile": str(session_key),
            }}
            result = subprocess.run(
                [sys.executable, str(repo / "plugins/modules/bind_reverse_records.py")],
                input=json.dumps(args), text=True, capture_output=True,
                env=dict(os.environ, PYTHONPATH=str(tmp_path / "collections")),
                timeout=20,
            )
            assert result.returncode == 0, result.stdout + result.stderr
            assert json.loads(result.stdout)["changed"] is True
            response = dns.query.tcp(dns.message.make_query(OWNER, "PTR"),
                                     "127.0.0.1", port=port)
            assert str(response.answer[0][0]) == "vpn.infra.example."
        finally:
            process.terminate()
            process.wait(timeout=10)
