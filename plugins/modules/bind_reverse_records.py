#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""Apply inventory PTR records to live dynamic reverse zones."""

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

IMPORT_ERROR = None
try:
    from ansible_collections.bodsch.dns.plugins.module_utils.bind_zone.reverse_updates import (
        ReverseRecordUpdater,
    )
except ImportError as exc:
    IMPORT_ERROR = str(exc)

DOCUMENTATION = r"""
module: bind_reverse_records
short_description: Reconcile inventory PTR records in dynamic reverse zones
version_added: "1.5.0"
author:
  - "Buo-ren Lin (@brlin-tw)"
description:
  - Query the authoritative server and update inventory-declared PTR RRsets.
  - Preserve records at owners not declared in the inventory.
  - Use reverse policy or ACL keys, or the session key for a local policy.
  - The server must already be running with the desired zone configuration.
requirements:
  - dnspython
options:
  zones:
    description: Raw C(bind_zones) definitions.
    required: true
    type: list
    elements: dict
  keys:
    description: TSIG keys from C(bind_update_keys).
    type: list
    elements: dict
    default: []
    suboptions:
      name:
        description: TSIG key name.
        type: str
        required: true
      algorithm:
        description: TSIG algorithm.
        type: str
        required: true
      secret:
        description: Base64 TSIG secret.
        type: str
        required: true
  server:
    description: IP address of the authoritative primary.
    type: str
    default: 127.0.0.1
  port:
    description: DNS server port.
    type: int
    default: 53
  session_keyfile:
    description: BIND session key path for C(reverse_update_policy.mode=local).
    type: path
    default: /run/named/session.key
attributes:
  check_mode:
    support: full
"""

EXAMPLES = r"""
- name: Reconcile dynamic reverse records
  bodsch.dns.bind_reverse_records:
    zones: "{{ bind_zones }}"
    keys: "{{ bind_update_keys }}"
"""

RETURN = r"""
changed:
  description: Whether any inventory PTR RRset changed or would change.
  returned: always
  type: bool
"""


def main():
    module = AnsibleModule(
        argument_spec=dict(
            zones=dict(type="list", elements="dict", required=True),
            keys=dict(type="list", elements="dict", default=[], options=dict(
                name=dict(type="str", required=True),
                algorithm=dict(type="str", required=True),
                secret=dict(type="str", required=True, no_log=True),
            )),
            server=dict(type="str", default="127.0.0.1"),
            port=dict(type="int", default=53),
            session_keyfile=dict(type="path", default="/run/named/session.key"),
        ),
        supports_check_mode=True,
    )
    if IMPORT_ERROR:
        module.fail_json(msg=missing_required_lib("dnspython"), exception=IMPORT_ERROR)
    updater = ReverseRecordUpdater(
        server=module.params["server"], port=module.params["port"],
        session_keyfile=module.params["session_keyfile"],
    )
    try:
        changed = updater.reconcile(module.params["zones"], module.params["keys"],
                                    check_mode=module.check_mode)
    except Exception as exc:
        module.fail_json(msg=str(exc), changed=updater.changed)
    module.exit_json(changed=changed)


if __name__ == "__main__":
    main()
