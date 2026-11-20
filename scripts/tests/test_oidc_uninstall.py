#!/usr/bin/env python3
"""Private-path, inert-command uninstall ordering; no installed host actions."""

import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class BrokerUninstall(unittest.TestCase):
    def run_uninstall(self, fault):
        with tempfile.TemporaryDirectory(
            prefix="mcpmac-oidc-uninstall-", dir=ROOT / "target"
        ) as temp:
            base = Path(temp)
            support = base / "host/Library/Application Support/EnterpriseEnclave"
            app = support / "EnclaveOIDC.app/Contents/MacOS/enclave-oidc"
            app.parent.mkdir(parents=True)
            app.write_text("fixture executable")
            pins = support / "codesign-pins.json"
            pins.write_text("fixture pins")
            agent = (
                base
                / "host/Library/LaunchAgents/com.enterprise.enclave.oidc-broker.plist"
            )
            agent.parent.mkdir(parents=True)
            agent.write_text("fixture plist")
            state = base / "state.json"
            job = "gui/502/com.enterprise.enclave.oidc-broker"
            state.write_text(json.dumps({"active": [job], "calls": [], "fault": fault}))
            helper = base / "launchctl.py"
            helper.write_text("""import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);s=json.loads(p.read_text());op,*args=sys.argv[2:];s['calls'].append([op,*args]);rc=0
if op=='print':
 rc=0 if args[0] in s['active'] else 1
 if args[0]=='system':
  rc=0;print('subdomains = {\\n unknown/502\\n}' if s['fault']=='domain-malformed' else 'missing domain inventory' if s['fault']=='domain-missing' else 'subdomains = {\\n user/502 [502]\\n}')
elif op=='bootout':
 if s['fault']=='stop':rc=1
 elif s['fault']!='stuck':s['active'].remove(args[0])
p.write_text(json.dumps(s));sys.exit(rc)
""")
            source = (ROOT / "packaging/macos/uninstall.sh").read_text()
            for path in [
                "/opt/enterprise",
                "/Library",
                "/var/db/enclave",
                "/var/run",
                "/var/log/enclave",
                "/etc",
            ]:
                source = source.replace(path, str(base / "host") + path)
            functions = f"""
uname() {{ echo Darwin; }}
id() {{ echo 0; }}
stat() {{ echo 501; }}
dscl() {{ echo 'fixture-user 502'; }}
sleep() {{ :; }}
pfctl() {{ :; }}
launchctl() {{ {shlex.quote(sys.executable)} {shlex.quote(str(helper))} {shlex.quote(str(state))} "$@"; }}
"""
            script = base / "uninstall.sh"
            script.write_text(functions + source)
            result = subprocess.run(
                ["/bin/sh", str(script)],
                env=dict(os.environ),
                capture_output=True,
                text=True,
                timeout=15,
            )
            return (
                result,
                json.loads(state.read_text()),
                app.exists(),
                pins.exists(),
                agent.exists(),
            )

    def test_unknown_inventory_preserves_programs_without_bootout(self):
        for fault in ["domain-missing", "domain-malformed"]:
            with self.subTest(fault=fault):
                result, state, app, pins, agent = self.run_uninstall(fault)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(app and pins and agent)
                self.assertFalse(any(call[0] == "bootout" for call in state["calls"]))

    def test_stop_refusal_preserves_app_pins_and_plist(self):
        result, state, app, pins, agent = self.run_uninstall("stop")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(app and pins and agent)
        self.assertIn(
            ["bootout", "gui/502/com.enterprise.enclave.oidc-broker"], state["calls"]
        )

    def test_loaded_after_bootout_preserves_app_pins_and_plist(self):
        result, _, app, pins, agent = self.run_uninstall("stuck")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(app and pins and agent)

    def test_success_stops_noncurrent_session_before_removing_payload(self):
        result, state, app, pins, agent = self.run_uninstall("none")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["active"], [])
        self.assertFalse(app or pins or agent)


if __name__ == "__main__":
    unittest.main()
