"""Regression tests for live reverse-zone inventory reconciliation."""

import copy

import dns.flags
import dns.message
import dns.opcode
import dns.rcode
import dns.rrset
import pytest

from test_bind_zone_reconciler import _load_bind_zone_module

updates = _load_bind_zone_module("reverse_updates")

KEYS = [{"name": "ddns", "algorithm": "hmac-sha256", "secret": "dGVzdA=="}]
ZONE = {
    "name": "infra.example", "type": "primary", "networks": ["192.168.3"],
    "ipv6_networks": ["2001:db8::/64"],
    "name_servers": ["ns1.infra.example."],
    "reverse_update_policy": {"mode": "rules", "rules": [
        {"action": "grant", "identity": "ddns", "ruletype": "zonesub", "types": ["PTR"]}
    ]},
    "hosts": [{"name": "wireguard", "ip": "192.168.3.10", "ipv6": "2001:db8::10"}],
}
OWNER = "10.3.168.192.in-addr.arpa."


class Server:
    def __init__(self):
        self.records = {
            "189.3.168.192.in-addr.arpa.": dns.rrset.from_text(
                "189.3.168.192.in-addr.arpa.", 300, "IN", "PTR", "ddns.example.")
        }
        self.updates = []
        self.refuse = False
        self.authoritative = True
        self.query_rcode = None

    def exchange(self, message, server, **kwargs):
        response = dns.message.make_response(message)
        if self.authoritative:
            response.flags |= dns.flags.AA
        if message.opcode() == dns.opcode.UPDATE:
            self.updates.append(message)
            if self.refuse:
                response.set_rcode(dns.rcode.REFUSED)
            else:
                # UPDATE delete/replace is scoped to an individual PTR RRset.
                assert all(rr.rdtype == dns.rdatatype.PTR for rr in message.authority)
                rr = message.authority[-1]
                self.records[rr.name.to_text()] = dns.rrset.from_text(
                    rr.name, rr.ttl, "IN", "PTR", *[str(rdata) for rdata in rr])
        else:
            rrset = self.records.get(message.question[0].name.to_text())
            if rrset:
                response.answer.append(rrset)
            else:
                response.set_rcode(dns.rcode.NXDOMAIN)
            if self.query_rcode is not None:
                response.set_rcode(self.query_rcode)
        return response


def test_missing_ptr_is_published_preserving_ddns_and_is_idempotent():
    server = Server()
    untouched = copy.deepcopy(server.records)
    updater = updates.ReverseRecordUpdater(exchange=server.exchange)
    assert updater.reconcile([ZONE], KEYS)
    assert len(server.updates) == 2  # IPv4 and IPv6
    assert str(server.records[OWNER][0]) == "wireguard.infra.example."
    for name, rrset in untouched.items():
        assert server.records[name] == rrset
    assert all(message.keyname.to_text() == "ddns." for message in server.updates)
    assert not updates.ReverseRecordUpdater(exchange=server.exchange).reconcile([ZONE], KEYS)
    assert len(server.updates) == 2


def test_check_mode_queries_without_updating():
    server = Server()
    original = copy.deepcopy(server.records)
    assert updates.ReverseRecordUpdater(exchange=server.exchange).reconcile(
        [ZONE], KEYS, check_mode=True)
    assert not server.updates
    assert server.records == original


def test_existing_ptr_replaced_with_value_prerequisite():
    server = Server()
    server.records[OWNER] = dns.rrset.from_text(OWNER, 300, "IN", "PTR", "old.example.")
    assert updates.ReverseRecordUpdater(exchange=server.exchange).reconcile([ZONE], KEYS)
    prerequisite = server.updates[0].answer[0]
    assert str(prerequisite[0]) == "old.example."
    assert str(server.records[OWNER][0]) == "wireguard.infra.example."
    assert server.records[OWNER].ttl == 86400


def test_refused_update_fails():
    server = Server()
    server.refuse = True
    with pytest.raises(updates.ReverseUpdateError, match="refused"):
        updates.ReverseRecordUpdater(exchange=server.exchange).reconcile([ZONE], KEYS)
    assert OWNER not in server.records


@pytest.mark.parametrize("authoritative,rcode", [(False, None), (True, dns.rcode.SERVFAIL)])
def test_bad_query_is_not_treated_as_a_missing_ptr(authoritative, rcode):
    server = Server()
    server.authoritative, server.query_rcode = authoritative, rcode
    with pytest.raises(updates.ReverseUpdateError, match="failed PTR query"):
        updates.ReverseRecordUpdater(exchange=server.exchange).reconcile([ZONE], KEYS)
    assert not server.updates


def test_missing_key_fails_without_unsigned_policy_update():
    server = Server()
    with pytest.raises(updates.ReverseUpdateError, match="No bind_update_keys"):
        updates.ReverseRecordUpdater(exchange=server.exchange).reconcile([ZONE])
    assert not server.updates


def test_static_and_secondary_zones_are_not_updated():
    server = Server()
    secondary = dict(ZONE, type="secondary", primaries=["192.168.3.70"])
    del secondary["reverse_update_policy"]
    static = dict(ZONE)
    del static["reverse_update_policy"]
    assert not updates.ReverseRecordUpdater(exchange=server.exchange).reconcile([secondary])
    assert not updates.ReverseRecordUpdater(exchange=server.exchange).reconcile([static])
    assert not server.updates


def test_local_policy_uses_session_key(tmp_path):
    session = tmp_path / "session.key"
    session.write_text('key "local-ddns" { algorithm hmac-sha256; secret "dGVzdA=="; };')
    server = Server()
    zone = dict(ZONE, reverse_update_policy={"mode": "local"})
    assert updates.ReverseRecordUpdater(
        exchange=server.exchange, session_keyfile=str(session)).reconcile([zone])
    assert all(message.keyname.to_text() == "local-ddns." for message in server.updates)


def test_inherited_acl_key_and_explicit_empty_reverse_acl():
    server = Server()
    zone = dict(ZONE, allow_updates=['key "ddns"'])
    del zone["reverse_update_policy"]
    updater = updates.ReverseRecordUpdater(exchange=server.exchange)
    assert updater.reconcile([zone], KEYS)
    assert all(message.keyname.to_text() == "ddns." for message in server.updates)
    zone["reverse_allow_updates"] = []
    assert not updates.ReverseRecordUpdater(exchange=server.exchange).reconcile([zone], KEYS)
