-- Verify Enclave LaunchDaemons and LaunchAgents Status and Disabled State
SELECT label, name, path, disabled, run_at_load, keep_alive
FROM launchd
WHERE label IN (
  'com.enterprise.enclave.supervisor',
  'com.enterprise.enclave.adapter',
  'com.enterprise.enclave.cas',
  'com.enterprise.enclave.apfs-broker',
  'com.enterprise.enclave.custody',
  'com.enterprise.enclave.ifc',
  'com.enterprise.enclave.zk',
  'com.enterprise.enclave.hydrate',
  'com.enterprise.enclave.browser',
  'com.enterprise.enclave.intent'
);
