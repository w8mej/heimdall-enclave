#!/usr/bin/env python3
"""Render the committed BTM template for one explicit deployment profile."""

import argparse
import pathlib
import plistlib
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--profile", required=True, choices=("L1", "L2", "L3"))
parser.add_argument("--out", type=pathlib.Path)
args = parser.parse_args()
with pathlib.Path(__file__).with_name("MCPMac-Enclave.mobileconfig").open(
    "rb"
) as stream:
    document = plistlib.load(stream)
for payload in document["PayloadContent"]:
    if (
        payload.get("PayloadType") == "com.apple.servicemanagement"
        and args.profile != "L3"
    ):
        payload["Rules"] = [
            rule
            for rule in payload["Rules"]
            if rule.get("RuleValue") != "com.enterprise.enclave.apfs-broker"
        ]
document["PayloadDescription"] += f"; deployment profile {args.profile}"
output = plistlib.dumps(document, fmt=plistlib.FMT_XML, sort_keys=False)
if args.out:
    args.out.write_bytes(output)
else:
    sys.stdout.buffer.write(output)
