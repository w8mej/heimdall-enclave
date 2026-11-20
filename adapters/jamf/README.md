# Jamf Pro Adapter for MCPMac Enclave (FS-706)

This directory contains integration scripts and Extension Attributes (EAs) for deploying and governing the MCPMac Enclave across macOS fleets using Jamf Pro.

## 1. Parameter Conventions (D-R15)

Jamf Pro reserves the first three script arguments:

- `$1`: Target drive mount point (e.g. `/`)
- `$2`: Computer name
- `$3`: Username

Therefore, per **D-R15**, `jamf_deploy_enclave.sh` uses positional parameters starting strictly at `$4`:

- **Parameter 4 (`$4`):** Model Target Slug (default: `llada-8b-instruct`)
- **Parameter 5 (`$5`):** Deployment Profile Tier (`L1`, `L2`, or `L3`; default: `L3`)
- **Parameter 6 (`$6`):** Deployment Action (`bootstrap`, `hydrate`, `healthcheck`, or `purge`; default: `bootstrap`)

## 2. Jamf Pro Policies

### Policy A: Zero-Touch Automated Fleet Bootstrap

- **Trigger:** Recurring Check-in, Enrollment Complete
- **Execution Frequency:** Once per computer
- **Payloads:**
  1. **Packages:** `MCPMac-Enclave-3.0.0.pkg` (Action: Install)
  2. **Configuration Profiles:** `MCPMac-Enclave.mobileconfig` (BTM & Notifications)
  3. **Scripts:** `jamf_deploy_enclave.sh`
     - Parameter 4: `llada-8b-instruct`
     - Parameter 5: `L3`
     - Parameter 6: `bootstrap`
- **Maintenance:** Run Recon after execution.

### Policy B: Self Service Model Weight Hydration

- **Category:** AI & Developer Tools
- **Self Service Description:** "Synchronize and cryptographically verify local frontier AI weights."
- **Payloads:**
  1. **Scripts:** `jamf_deploy_enclave.sh`
     - Parameter 4: `llada-8b-instruct`
     - Parameter 5: `L3`
     - Parameter 6: `hydrate`
- **User Experience:** Returns in < 5 seconds while background daemon (`com.enterprise.enclave.hydrate`) completes streaming Bao transfer.

## 3. Extension Attributes (EAs)

### `EA-Enclave-Status.sh`

- **Data Type:** String
- **Input Type:** Script
- **Values:** `healthy`, `unhealthy`, `quarantined`, `NOT_INSTALLED`, `UNKNOWN`
- Polls `/opt/enterprise/enclave/bin/mcp-enclave deploy healthcheck --profile "$ENCLAVE_PROFILE" --json`, with the configuration below.

### `EA-Enclave-Security.sh`

- **Data Type:** String
- **Input Type:** Script
- **Values:** `ISOLATED`, `EXPOSED`, `QUARANTINED`, `NOT_INSTALLED`.
- Requires successful authenticated health and canonical packet filter observations before reporting `ISOLATED`.

### Profile configuration for each managed cohort

Both EAs accept `ENCLAVE_PROFILE=L1`, `L2` or `L3`; an unset variable defaults
to `L2`. Configure the variable explicitly in the managed script invocation or
prepend, for example, `export ENCLAVE_PROFILE=L3` to the cohort's deployed EA
script. Match the profile supplied to `jamf_deploy_enclave.sh` parameter 5.
That deployment parameter does not automatically configure independently run EAs.
Do not rely on an interactive user's shell environment. No automatic profile
discovery is performed; the health CLI continues to require matching daemon
profile replies and L3 broker readiness.

Empty or invalid values produce a diagnostic and stop before invoking the CLI.
The status EA reports `UNKNOWN`; the security EA reports `EXPOSED`. CLI failures
and malformed replies cannot establish healthy/isolation status. This explicit
configuration and its inert tests do not establish signed installed acceptance.

## 4. Smart Computer Groups

### Smart Group: `Enclave - Fully Compliant`

- Criteria:
  - `EA-Enclave-Status` is `healthy`
  - AND `EA-Enclave-Security` is `ISOLATED`
  - AND `FileVault 2` is `All Partitions Encrypted`
  - AND `SIP Status` is `Enabled`

### Smart Group: `Enclave - Security Remediation Required`

- Criteria:
  - `EA-Enclave-Status` is not `NOT_INSTALLED`
  - AND `EA-Enclave-Security` is `EXPOSED`
- Action: Automated policy triggers `mcp-enclave deploy install --profile L3` to reload anchors.

## References

1. Jamf: *Jamf Pro Documentation — Scripts in Policies (Positional Parameters $1-$11)*. URL: `https://learn.jamf.com/en-US/bundle/jamf-pro-documentation-current/page/Scripts.html` (Accessed 2026-11-06).
2. Jamf: *Jamf Pro Documentation — Computer Extension Attributes*. URL: `https://learn.jamf.com/en-US/bundle/jamf-pro-documentation-current/page/Computer_Extension_Attributes.html` (Accessed 2026-11-06).
