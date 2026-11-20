-- Verify Enclave TUF Repository, Signed Host Config, Policy, and Quarantine State
SELECT path, directory, filename, size, mode, uid, gid
FROM file
WHERE path IN (
  '/var/db/enclave/cas/tuf/root.json',
  '/Library/Application Support/EnterpriseEnclave/tuf/root.json',
  '/var/db/enclave/apfs-broker/tuf/repo/targets.json',
  '/var/db/enclave/apfs-broker/tuf/repo/enclave-distribution-v1.json',
  '/var/db/enclave/apfs-broker/state/apfs-publications.sealed',
  '/var/db/enclave/apfs-broker/state/apfs-publications.gen',
  '/var/db/enclave/apfs-broker/deployment.quiesced',
  '/var/db/enclave/cas/tuf/repo/targets.json',
  '/opt/enterprise/enclave/cas/enclave-host-config.json',
  '/opt/enterprise/enclave/cas/enclave-policy.cedar.v1.json',
  '/var/db/enclave/quarantined'
);
