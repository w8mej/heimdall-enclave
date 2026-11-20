#!/usr/bin/env python3
"""Production shell control flow against private paths and inert host commands.

This does not run launchd/PF or establish native scheduling, reboot or signal
survival. No production test hook or environment override is introduced.
"""

import json
import plistlib
import shlex
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RULES = "block drop quick out all\npass quick on lo0 all\n"


class BreakGlassRecovery(unittest.TestCase):
    @contextmanager
    def fixture(self, fault="none"):
        with tempfile.TemporaryDirectory(prefix="mcpmac-break-glass-recovery-") as tmp:
            base = Path(tmp)
            for name in ("var/run", "var/log", "Library/LaunchDaemons"):
                (base / name).mkdir(parents=True)
            state = base / "host.json"
            state.write_text(
                json.dumps(
                    dict(
                        calls=[],
                        fault=fault,
                        loaded=False,
                        live_rules=RULES,
                        sleep_count=0,
                    )
                )
            )
            helper = base / "host.py"
            helper.write_text("""import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);s=json.loads(p.read_text());tool,*args=sys.argv[2:];s['calls'].append([tool,*args]);rc=0;out=''
if tool=='uname':out='Darwin\\n'
elif tool=='id':out='0\\n'
elif tool=='launchctl':
 if args[0]=='bootstrap':
  job=pathlib.Path(args[-1]);s['plist']=job.read_text();s['watchdog']=job.parent.parent.parent/'var/run/enclave-break-glass/watchdog';s['watchdog']=str(s['watchdog']);s['loaded']=True
  if s['fault']=='bootstrap':rc=1
 elif args[0]=='print':rc=0 if s['loaded'] else 1
 elif args[0]=='bootout':
  if s['fault'] in ['bootout','bootstrap']:rc=1
  elif s['fault']!='stuck':s['loaded']=False
elif tool=='pfctl':
 if args[-1]=='-sr':out=s['live_rules']
 elif '-F' in args:s['live_rules']=''
 elif '-f' in args:
  s['restore_attempts']=s.get('restore_attempts',0)+1
  if s['fault']=='restore' or (s['fault']=='watchdog-restore' and s['restore_attempts']<3):rc=1
  else:s['live_rules']=pathlib.Path(args[-1]).read_text()
elif tool=='logger':
 if s['fault']=='logger' or (s['fault']=='relock-log' and args[-1].startswith('RELOCK')):rc=1
elif tool=='sleep':
 s['sleep_count']+=1
 if s.get('watchdog_mode') and s['sleep_count']>=4:rc=99
p.write_text(json.dumps(s));print(out,end='');sys.exit(rc)
""")
            source = (ROOT / "scripts/break-glass.sh").read_text()
            for path in ("/var/run", "/var/log", "/Library"):
                source = source.replace(path, str(base) + path)
            prelude = ""
            for name, path in dict(
                uname="/usr/bin/uname",
                id="/usr/bin/id",
                launchctl="/bin/launchctl",
                pfctl="/sbin/pfctl",
                logger="/usr/bin/logger",
                sleep="/bin/sleep",
            ).items():
                source = source.replace(path, "fixture_" + name)
                prelude += (
                    "fixture_"
                    + name
                    + "() { "
                    + shlex.quote(sys.executable)
                    + " "
                    + shlex.quote(str(helper))
                    + " "
                    + shlex.quote(str(state))
                    + " "
                    + name
                    + ' "$@"; }\n'
                )
            # Function definitions appear both in the parent and generated child.
            source = source.replace(
                "#!/bin/sh\nset -eu", "#!/bin/sh\n" + prelude + "set -eu"
            )
            script = base / "break-glass.sh"
            script.write_text(prelude + source)
            result = subprocess.run(
                ["/bin/bash", str(script), "--ticket", "INC-123", "--duration", "30s"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            yield result, state, base

    def test_normal_completion_restores_exact_snapshot_and_drains_watchdog(self):
        with self.fixture() as (result, state, base):
            final = json.loads(state.read_text())
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(final["live_rules"], RULES)
            self.assertFalse(final["loaded"])
            self.assertFalse((base / "var/run/enclave-break-glass").exists())
            self.assertFalse(
                (
                    base
                    / "Library/LaunchDaemons/com.enterprise.enclave.break-glass-watchdog.plist"
                ).exists()
            )
            flush = next(
                i for i, c in enumerate(final["calls"]) if c[0] == "pfctl" and "-F" in c
            )
            bootstrap = next(
                i
                for i, c in enumerate(final["calls"])
                if c[:2] == ["launchctl", "bootstrap"]
            )
            self.assertLess(bootstrap, flush)

    def test_failed_bootout_retains_snapshot_job_and_reports_failure(self):
        with self.fixture("bootout") as (result, state, base):
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(json.loads(state.read_text())["loaded"])
            self.assertEqual(
                (base / "var/run/enclave-break-glass/rules").read_text(), RULES
            )
            self.assertTrue(
                (
                    base
                    / "Library/LaunchDaemons/com.enterprise.enclave.break-glass-watchdog.plist"
                ).exists()
            )

    def test_successful_bootout_without_disappearance_retains_recovery_files(self):
        with self.fixture("stuck") as (result, state, base):
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(json.loads(state.read_text())["loaded"])
            self.assertTrue((base / "var/run/enclave-break-glass/rules").exists())

    def test_restore_failure_retains_watchdog_and_snapshot(self):
        with self.fixture("restore") as (result, state, base):
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(json.loads(state.read_text())["loaded"])
            self.assertEqual(
                (base / "var/run/enclave-break-glass/rules").read_text(), RULES
            )

    def test_relock_logger_failure_still_drains_after_successful_restore(self):
        with self.fixture("relock-log") as (result, state, base):
            final = json.loads(state.read_text())
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(final["live_rules"], RULES)
            self.assertFalse(final["loaded"])
            self.assertFalse((base / "var/run/enclave-break-glass").exists())

    def test_open_logger_failure_never_flushes_and_still_drains(self):
        with self.fixture("logger") as (result, state, base):
            final = json.loads(state.read_text())
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(final["live_rules"], RULES)
            self.assertFalse(any(c[0] == "pfctl" and "-F" in c for c in final["calls"]))
            self.assertFalse(final["loaded"])
            self.assertFalse((base / "var/run/enclave-break-glass").exists())

    def test_uncertain_failed_bootstrap_retains_recovery_files_without_opening(self):
        with self.fixture("bootstrap") as (result, state, base):
            self.assertNotEqual(result.returncode, 0)
            final = json.loads(state.read_text())
            self.assertFalse(any(c[0] == "pfctl" and "-F" in c for c in final["calls"]))
            self.assertTrue(final["loaded"])
            self.assertTrue((base / "var/run/enclave-break-glass/rules").exists())

    def run_watchdog(self, state, base, fault="none"):
        initial = json.loads(state.read_text())
        initial.update(
            fault=fault,
            calls=[],
            sleep_count=0,
            restore_attempts=0,
            watchdog_mode=True,
            live_rules="",
        )
        state.write_text(json.dumps(initial))
        result = subprocess.run(
            ["/bin/sh", str(base / "var/run/enclave-break-glass/watchdog"), "30"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result, json.loads(state.read_text())

    def test_watchdog_retries_restore_even_if_logging_fails(self):
        with self.fixture("restore") as (_, state, base):
            result, final = self.run_watchdog(state, base, "logger")
            restores = [c for c in final["calls"] if c[0] == "pfctl" and "-f" in c]
            self.assertGreaterEqual(len(restores), 3, result.stderr)
            self.assertEqual(final["live_rules"], RULES)

    def test_watchdog_restart_does_not_repeat_open_interval(self):
        with self.fixture("restore") as (_, state, base):
            _, first = self.run_watchdog(state, base)
            _, second = self.run_watchdog(state, base)
            self.assertIn(["sleep", "30"], first["calls"])
            self.assertNotIn(["sleep", "30"], second["calls"])
            self.assertEqual(second["calls"][0][0], "pfctl")
            self.assertEqual(second["live_rules"], RULES)
            # Serialized contract only: actual launchd restart remains NOT RUN.
            plist = plistlib.loads(first["plist"].encode())
            self.assertIs(plist.get("KeepAlive"), True)
            self.assertGreaterEqual(plist.get("ThrottleInterval", 0), 1)

    def test_watchdog_keeps_retrying_transient_pf_restore_failure(self):
        with self.fixture("restore") as (_, state, base):
            _, final = self.run_watchdog(state, base, "watchdog-restore")
            self.assertGreaterEqual(final["restore_attempts"], 3)
            self.assertEqual(final["live_rules"], RULES)


if __name__ == "__main__":
    unittest.main()
