#!/usr/bin/env python3
"""Run installer control flow with private filesystem and inert PF/launchd fixtures.

Fixed installation paths are rewritten into a TemporaryDirectory; only privileged
or unavailable host commands are substituted. This is failure-ordering evidence,
not real Darwin PF, launchd, signature, account or hardware validation.
"""

import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LABELS = [
    "com.enterprise.enclave." + name
    for name in (
        "supervisor",
        "zk",
        "custody",
        "cas",
        "adapter",
        "ifc",
        "browser",
        "hydrate",
        "gateway",
    )
]


class InstallerRecovery(unittest.TestCase):
    def run_install(self, fault="none", no_bootstrap=False, console_uid=0):
        with tempfile.TemporaryDirectory(
            prefix="mcpmac-installer-recovery-", dir=ROOT / "target"
        ) as tmp:
            base = Path(tmp)
            dist = base / "input"
            for name in (
                "bin",
                "launchd",
                "EnclaveCustody.app",
                "EnclaveOIDC.app/Contents/MacOS",
                "fido-mds",
                "tuf/repo",
            ):
                (dist / name).mkdir(parents=True)
            (dist / "EnclaveOIDC.app/Contents/MacOS/enclave-oidc").write_text(
                "fixture broker"
            )
            (dist / "EnclaveOIDC.app/Contents/MacOS/enclave-oidc").chmod(0o755)
            if fault == "missing-oidc":
                (dist / "EnclaveOIDC.app/Contents/MacOS/enclave-oidc").unlink()
            (dist / "codesign-pins.json").write_text("{}")
            if fault == "fixture-authorities":
                (dist / "FIXTURE-AUTHORITIES.txt").write_text("SYNTHETIC FIXTURE ONLY")
            (dist / "yubikey-transport").write_text("hid")
            if fault == "transport":
                (dist / "yubikey-transport").write_text("unsupported")
            (dist / "fido-mds/yubico.json").write_text('{"entries":[]}')
            if fault == "missing-mds":
                (dist / "fido-mds/yubico.json").unlink()
            (dist / "launchd/provision-accounts.sh").write_text(":\n")
            (dist / "launchd/test.sb").write_text("(version 1)")
            (dist / "launchd/com.enterprise.enclave.intent.plist").write_text(
                "old intent"
            )
            for trust_name in (
                "root.json",
                "timestamp.json",
                "snapshot.json",
                "targets.json",
                "enclave-host-config.json",
                "enclave-policy.cedar.v1.json",
                "vk_manifest.json",
                "enclave-distribution-v1.json",
            ):
                (dist / "tuf/repo" / trust_name).write_text("{}")
            state = base / "state.json"
            state.write_text(
                json.dumps(
                    {
                        "calls": [],
                        "active": {label: True for label in LABELS},
                        "fault": fault,
                    }
                )
            )
            if fault == "no-prior-jobs":
                state.write_text(
                    json.dumps({"calls": [], "active": {}, "fault": fault})
                )
            if fault in ("fido-stop", "gui-stop"):
                initial = json.loads(state.read_text())
                initial["active"][
                    "com.enterprise.enclave."
                    + ("fido" if fault == "fido-stop" else "intent")
                ] = True
                state.write_text(json.dumps(initial))
            if fault == "oidc-stop":
                initial = json.loads(state.read_text())
                initial["active"]["com.enterprise.enclave.oidc-broker"] = True
                state.write_text(json.dumps(initial))
            if console_uid == 501:
                initial = json.loads(state.read_text())
                initial["active"]["com.enterprise.enclave.intent"] = True
                state.write_text(json.dumps(initial))
            helper = base / "host.py"
            helper.write_text("""import json,sys,pathlib
p=pathlib.Path(sys.argv[1]);s=json.loads(p.read_text());tool,*args=sys.argv[2:];s['calls'].append([tool,*args]);rc=0;out=''
if tool=='launchctl':
 op=args[0]
 if op=='print':
  label=args[1].split('/')[-1];rc=0 if s['active'].get(label) else 1;out='state = running\\n'
  if args[1]=='system':rc=0;out='subdomains = {\\n user/502 [502]\\n}\\n'
  if args[1]=='system' and s['fault']=='domain-missing':out='unrecognized format\\n'
  if args[1]=='system' and s['fault']=='domain-malformed':out='subdomains = {\\n external/502\\n}\\n'
  if args[1]=='system' and s['fault']=='domain-error':rc=1
 elif op=='bootout':
  label=args[-1].split('/')[-1].removesuffix('.plist')
  if label.endswith('.intent'):s.setdefault('intent_stop_payload_states',[]).append((p.parent/'host/opt/enterprise/enclave/bin/mcp-enclave').exists())
  if label.endswith('.oidc-broker'):s.setdefault('oidc_stop_payload_states',[]).append((p.parent/'host/opt/enterprise/enclave/bin/mcp-enclave').exists())
  if (s['fault']=='cleanup' and s.get('attempted') and label.endswith('.supervisor')) or (s['fault']=='stop' and label.endswith('.cas')) or (s['fault']=='fido-stop' and label.endswith('.fido')) or (s['fault']=='gui-stop' and label.endswith('.intent')) or (s['fault']=='oidc-stop' and label.endswith('.oidc-broker')):rc=1
  else:s['active'][label]=False
 elif op=='bootstrap':
  label=pathlib.Path(args[-1]).stem
  s['attempted']=True
  if s['fault'] in ['bootstrap','cleanup'] and label.endswith('.cas'):rc=1
  else:s['active'][label]=True
elif tool=='pfctl':
 if args==['-s','info']:out='Status: Enabled\\n'
 if s['fault']=='pf-load' and args and args[0]=='-f':rc=1
p.write_text(json.dumps(s));print(out,end='');sys.exit(rc)
""")
            cli = dist / "bin/mcp-enclave"
            cli.write_text(
                "#!/bin/sh\n"
                + ("exit 71\n" if fault == "preflight" else "")
                + 'case " $* " in\n'
                ' *" launchd render "*)\n'
                + ("exit 72\n" if fault == "render" else "")
                + 'while [ "$1" != --out ]; do shift; done; shift; mkdir -p "$1"\n'
                + "for label in "
                + " ".join(
                    LABELS
                    + [
                        "com.enterprise.enclave.intent",
                        "com.enterprise.enclave.oidc-broker",
                    ]
                )
                + '; do echo plist > "$1/$label.plist"; done; echo profile > "$1/test.sb";;\n'
                ' *" launchd grant-key "*) echo "{}";;\nesac\n'
            )
            cli.chmod(0o755)
            for path in (
                "var/run",
                "etc",
                "Library/LaunchDaemons",
                "var/db/enclave",
                "Library/LaunchAgents",
                "opt/enterprise/enclave/cas",
            ):
                (base / "host" / path).mkdir(parents=True, exist_ok=True)
            (base / "host/etc/pf.conf").write_text("# prior conf\n")
            pin = (
                base
                / "host/Library/Application Support/EnterpriseEnclave/tuf/root.json"
            )
            if fault in ("root-rotation", "unsafe-root-pin"):
                pin.parent.mkdir(parents=True)
                if fault == "root-rotation":
                    pin.write_text("original-independent-bootstrap-pin")
                else:
                    pin.symlink_to(dist / "tuf/repo/root.json")

            for label in LABELS:
                (base / "host/Library/LaunchDaemons" / (label + ".plist")).write_text(
                    "prior plist"
                )
            (
                base / "host/Library/LaunchAgents/com.enterprise.enclave.intent.plist"
            ).write_text("prior GUI plist")
            source = (ROOT / "packaging/macos/install.sh").read_text()
            for path in (
                "/opt/enterprise",
                "/Library",
                "/var/db/enclave",
                "/var/run",
                "/etc",
            ):
                source = source.replace(path, str(base / "host") + path)
            source = source.replace("/usr/bin/plutil", "fixture_plutil")
            fixtures = f"""
uname() {{ echo Darwin; }}
id() {{ echo 0; }}
chown() {{ :; }}
shasum() {{ :; }}
codesign() {{ :; }}
dscl() {{ echo 'fixture-user 502'; }}
sleep() {{ :; }}
stat() {{ case "$*" in *'%u %Lp'*) echo '0 444';; *) echo {console_uid};; esac; }}
fixture_plutil() {{ echo same-public-key; }}
launchctl() {{ {shlex.quote(sys.executable)} {shlex.quote(str(helper))} {shlex.quote(str(state))} launchctl "$@"; }}
pfctl() {{ {shlex.quote(sys.executable)} {shlex.quote(str(helper))} {shlex.quote(str(state))} pfctl "$@"; }}
ditto() {{ cp -R "$1" "$2"; }}
install() {{
  directory=0
  while [ "$#" -gt 0 ]; do
    case "$1" in -d) directory=1; shift;; -o|-g|-m) shift 2;; *) break;; esac
  done
  if [ "$directory" = 1 ]; then mkdir -p "$@"; else cp "$1" "$2"; fi
}}
"""
            script = base / "installer.sh"
            script.write_text(fixtures + source)
            result = subprocess.run(
                ["/bin/sh", str(script)] + (["--no-bootstrap"] if no_bootstrap else []),
                env=dict(os.environ, MCPMAC_DIST=str(dist)),
                capture_output=True,
                text=True,
                timeout=25,
            )
            final = json.loads(state.read_text())
            final["retained_stage"] = bool(
                list((base / "host/var/run").glob("enclave-stage.*"))
            )
            final["payload_published"] = (
                base / "host/opt/enterprise/enclave/bin/mcp-enclave"
            ).exists()
            final["bootstrap_pin"] = pin.read_text() if pin.exists() else None
            cas = base / "host/opt/enterprise/enclave/cas"
            final["runtime_payloads"] = {
                name: (cas / name).read_text()
                for name in (
                    "enclave-host-config.json",
                    "enclave-policy.cedar.v1.json",
                    "vk_manifest.json",
                    "enclave-distribution-v1.json",
                )
                if (cas / name).is_file()
            }

            return result, final

    def test_unknown_or_unavailable_live_domain_inventory_refuses_before_changes(self):
        for fault in ["domain-missing", "domain-malformed", "domain-error"]:
            with self.subTest(fault=fault):
                result, state = self.run_install(fault)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(state["payload_published"])
                self.assertFalse(
                    any(c[:2] == ["launchctl", "bootout"] for c in state["calls"])
                )

    def test_missing_browser_broker_refuses_before_host_changes(self):
        result, state = self.run_install("missing-oidc")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(state["payload_published"])
        self.assertFalse(any(c[:2] == ["launchctl", "bootout"] for c in state["calls"]))

    def test_noncurrent_browser_broker_stop_failure_preserves_payload(self):
        result, state = self.run_install("oidc-stop", console_uid=501)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(state["payload_published"])
        self.assertTrue(state["active"]["com.enterprise.enclave.oidc-broker"])
        self.assertTrue(
            any(
                c[:3]
                == ["launchctl", "print", "gui/502/com.enterprise.enclave.oidc-broker"]
                for c in state["calls"]
            )
        )
        self.assertTrue(
            all(value is False for value in state["oidc_stop_payload_states"])
        )

    def test_fixture_authority_marker_cannot_become_production_installation(self):
        result, state = self.run_install("fixture-authorities")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(state["payload_published"])
        self.assertFalse(any(c[:2] == ["launchctl", "bootout"] for c in state["calls"]))

    def test_existing_independent_bootstrap_pin_survives_upgrade(self):
        result, state = self.run_install("root-rotation")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["bootstrap_pin"], "original-independent-bootstrap-pin")
        self.assertEqual(
            state["runtime_payloads"],
            {
                name: "{}"
                for name in (
                    "enclave-host-config.json",
                    "enclave-policy.cedar.v1.json",
                    "vk_manifest.json",
                    "enclave-distribution-v1.json",
                )
            },
        )

    def test_unsafe_existing_bootstrap_pin_refuses_before_host_changes(self):
        result, state = self.run_install("unsafe-root-pin")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(state["payload_published"])
        self.assertFalse(any(c[:2] == ["launchctl", "bootout"] for c in state["calls"]))

    def test_missing_mds_does_not_stop_prior_jobs(self):
        result, state = self.run_install("missing-mds")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(
            all(state["active"].get(label) for label in LABELS),
            result.stdout + result.stderr,
        )
        self.assertFalse(any(c[:2] == ["launchctl", "bootout"] for c in state["calls"]))

    def test_render_failure_does_not_stop_prior_jobs(self):
        result, state = self.run_install("render")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(
            all(state["active"].get(label) for label in LABELS),
            result.stdout + result.stderr,
        )
        self.assertFalse(any(c[:2] == ["launchctl", "bootout"] for c in state["calls"]))

    def test_partial_bootstrap_failure_stops_all_new_jobs(self):
        result, state = self.run_install("bootstrap")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(
            any(state["active"].get(label) for label in LABELS),
            result.stdout + result.stderr,
        )
        self.assertTrue(
            any(c[:2] == ["launchctl", "bootstrap"] for c in state["calls"])
        )

    def test_pf_load_failure_starts_no_new_jobs(self):
        result, state = self.run_install("pf-load")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(
            any(c[:2] == ["launchctl", "bootstrap"] for c in state["calls"])
        )

    def test_success_keeps_jobs_and_loads_pf_first(self):
        result, state = self.run_install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(all(state["active"].get(label) for label in LABELS))
        pf = next(i for i, c in enumerate(state["calls"]) if c[:2] == ["pfctl", "-f"])
        bootstrap = next(
            i
            for i, c in enumerate(state["calls"])
            if c[:2] == ["launchctl", "bootstrap"]
        )
        self.assertLess(pf, bootstrap)

    def test_unknown_transport_refuses_before_stopping_jobs(self):
        result, state = self.run_install("transport")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(all(state["active"].get(label) for label in LABELS))
        self.assertFalse(any(c[:2] == ["launchctl", "bootout"] for c in state["calls"]))

    def test_cleanup_failure_retains_private_stage_and_reports_incomplete_recovery(
        self,
    ):
        result, state = self.run_install("cleanup")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(state["retained_stage"])
        self.assertIn("recovery could not stop", result.stderr)

    def test_failed_old_job_stop_recovers_only_prior_jobs_before_payload_replacement(
        self,
    ):
        result, state = self.run_install("stop")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to replace live payload", result.stderr)
        self.assertTrue(all(state["active"].get(label) for label in LABELS))
        self.assertFalse(any(c[0] == "pfctl" for c in state["calls"]))

    def test_no_bootstrap_refuses_live_payload_replacement_without_stopping_jobs(self):
        result, state = self.run_install(no_bootstrap=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(all(state["active"].get(label) for label in LABELS))
        self.assertFalse(state["payload_published"])
        self.assertFalse(any(c[:2] == ["launchctl", "bootout"] for c in state["calls"]))

    def test_no_bootstrap_preserves_offline_file_install_use(self):
        result, state = self.run_install("no-prior-jobs", no_bootstrap=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(state["payload_published"])
        self.assertFalse(
            any(c[:2] == ["launchctl", "bootstrap"] for c in state["calls"])
        )

    def test_hid_upgrade_refuses_replacement_if_old_emulator_cannot_stop(self):
        result, state = self.run_install("fido-stop")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(state["payload_published"])
        self.assertTrue(state["active"]["com.enterprise.enclave.fido"])
        self.assertTrue(all(state["active"].get(label) for label in LABELS))

    def test_upgrade_refuses_replacement_if_console_agent_cannot_stop(self):
        result, state = self.run_install("gui-stop", console_uid=501)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(state["payload_published"])
        self.assertTrue(state["active"]["com.enterprise.enclave.intent"])
        self.assertTrue(all(state["active"].get(label) for label in LABELS))

    def test_unknown_console_identity_refuses_before_payload_or_old_job_stop(self):
        result, state = self.run_install(console_uid="unavailable")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(state["payload_published"])
        self.assertTrue(all(state["active"].get(label) for label in LABELS))
        self.assertFalse(any(c[:2] == ["launchctl", "bootout"] for c in state["calls"]))

    def test_valid_upgrade_stops_console_agent_before_payload_and_restarts_it(self):
        result, state = self.run_install(console_uid=501)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(state["active"]["com.enterprise.enclave.intent"])
        self.assertIs(state["intent_stop_payload_states"][0], False)

    def test_failed_system_stop_recovers_unchanged_prior_console_agent(self):
        result, state = self.run_install("stop", console_uid=501)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(state["payload_published"])
        self.assertTrue(state["active"]["com.enterprise.enclave.intent"])
        self.assertTrue(
            any(
                c[:2] == ["launchctl", "bootstrap"] and c[2] == "gui/501"
                for c in state["calls"]
            )
        )


if __name__ == "__main__":
    unittest.main()
