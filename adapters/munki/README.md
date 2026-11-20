# Munki core health profile

The core package's `installcheck_script` accepts `ENCLAVE_PROFILE=L1`, `L2` or
`L3`; an unset variable defaults to `L2`. Configure the variable in the managed
execution environment or prepend, for example, `export ENCLAVE_PROFILE=L3` to
the installcheck script in the cohort's deployed pkginfo. Match the installed
daemon profile. Do not rely on an interactive user's environment; no automatic
profile discovery is performed.

The script passes the selected profile to the health CLI, which still requires
matching daemon profile replies and L3 broker readiness. Only a successful CLI
exit with a valid `details.overall_status` of `healthy` returns Munki's skip
installation exit 1. An empty/invalid profile stops before invoking the CLI,
reports a diagnostic and returns 0 (installation remains needed); CLI failures
or malformed replies also cannot establish a healthy skip. This does not grant
installation authorization or establish signed installed acceptance.

Profile propagation and refusal tests use private inert tools on Linux. On
Darwin the same tests use `/usr/bin/plutil`; neither mode queries installed
services or changes host configuration.
