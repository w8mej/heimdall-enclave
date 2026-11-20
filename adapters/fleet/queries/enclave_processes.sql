-- Verify Enclave Daemons Running Under Expected Dedicated UIDs
SELECT pid, name, path, uid, gid, phys_footprint
FROM processes
WHERE path LIKE '/opt/enterprise/enclave/bin/%'
   OR path LIKE '/Library/Application Support/EnterpriseEnclave/%';
