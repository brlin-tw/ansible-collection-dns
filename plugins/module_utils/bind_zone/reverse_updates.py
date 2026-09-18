"""Reconcile inventory PTR RRsets through the authoritative DNS server."""

from __future__ import annotations

import re
from pathlib import Path

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rcode
import dns.rdatatype
import dns.rrset
import dns.tsig
import dns.update

from .builder import ZoneSpecBuilder


class ReverseUpdateError(RuntimeError):
    """Raised when the authoritative server cannot reconcile a PTR RRset."""


class ReverseRecordUpdater:
    """Preserve runtime DDNS data while updating explicitly managed PTR owners."""

    def __init__(self, server="127.0.0.1", port=53, timeout=10,
                 session_keyfile="/run/named/session.key", exchange=None):
        self.server = server
        self.port = port
        self.timeout = timeout
        self.session_keyfile = session_keyfile
        self.exchange = exchange or dns.query.tcp
        self.changed = False

    def reconcile(self, zones, keys=(), check_mode=False):
        """Replace only inventory-declared PTR RRsets; never purge other owners."""
        raw_by_name = {zone["name"].rstrip("."): zone for zone in zones}
        for spec in ZoneSpecBuilder().build(zones).zone_files:
            if not (spec.is_reverse and spec.dynamic_updates
                    and spec.state == "present"):
                continue
            origin = dns.name.from_text(spec.origin)
            desired = {}
            for record in spec.records:
                if record.rtype != "PTR":
                    continue
                owner = dns.name.from_text(record.owner, origin=origin)
                rrset = desired.setdefault(
                    owner, dns.rrset.RRset(owner, 1, dns.rdatatype.PTR)
                )
                rrset.add(dns.rdata.from_text(1, "PTR", record.value),
                          record.ttl if record.ttl is not None else spec.default_ttl)
            for owner, rrset in desired.items():
                query = dns.message.make_query(owner, "PTR")
                query.flags &= ~dns.flags.RD
                response = self._exchange(query)
                if (response.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN)
                        or not response.flags & dns.flags.AA):
                    raise ReverseUpdateError(
                        f"Non-authoritative or failed PTR query for {owner}: "
                        f"{dns.rcode.to_text(response.rcode())}"
                    )
                current = next((answer for answer in response.answer
                                if answer.name == owner
                                and answer.rdtype == dns.rdatatype.PTR), None)
                if current == rrset and current.ttl == rrset.ttl:
                    continue
                if check_mode:
                    self.changed = True
                    continue
                raw = raw_by_name[spec.source_zone_name.rstrip(".")]
                credentials = self._credentials(raw, keys)
                for credential in credentials:
                    update = dns.update.Update(origin, keyring=credential)
                    if current is None:
                        update.absent(owner, "PTR")
                    else:
                        update.present(owner, *current)
                    update.replace(owner, rrset.ttl, *rrset)
                    result = self._exchange(update)
                    if result.rcode() == dns.rcode.NOERROR:
                        self.changed = True
                        break
                    if result.rcode() != dns.rcode.REFUSED:
                        raise ReverseUpdateError(
                            f"PTR update for {owner} failed: "
                            f"{dns.rcode.to_text(result.rcode())}"
                        )
                else:
                    raise ReverseUpdateError(
                        f"PTR update for {owner} refused; provide a bind_update_keys "
                        "key permitted to update this owner by the reverse policy/ACL"
                    )
        return self.changed

    def _exchange(self, message):
        return self.exchange(message, self.server, port=self.port, timeout=self.timeout)

    def _credentials(self, raw, keys):
        """Use reverse-policy keys, inherited ACL keys, or BIND's local key."""
        policy = raw.get("reverse_update_policy") or {}
        if policy.get("mode") == "local":
            text = Path(self.session_keyfile).read_text(encoding="utf-8")
            match = re.search(
                r'key\s+"([^"]+)"\s*\{\s*algorithm\s+([^;]+);\s*'
                r'secret\s+"([^"]+)";', text
            )
            if not match:
                raise ReverseUpdateError("Cannot parse the BIND session key file")
            name, algorithm, secret = match.groups()
            return [dns.tsig.Key(name, secret, algorithm.strip())]
        if policy:
            names = {str(rule["identity"]).rstrip(".").lower()
                     for rule in policy.get("rules", [])
                     if rule["action"] == "grant"}
        else:
            acl = raw.get("reverse_allow_updates", raw.get("allow_updates", []))
            names = set()
            for entry in acl:
                match = re.fullmatch(r'key\s+"?([^"\s;]+)"?;?', entry.strip())
                if match:
                    names.add(match[1].rstrip(".").lower())
        selected = [dns.tsig.Key(key["name"], key["secret"], key["algorithm"])
                    for key in keys if key["name"].rstrip(".").lower() in names]
        if policy and not selected:
            raise ReverseUpdateError(
                "No bind_update_keys key matches the reverse update-policy grants"
            )
        # Named ACLs and address-based grants may authorize an unsigned update.
        return selected if policy else selected + [None]
