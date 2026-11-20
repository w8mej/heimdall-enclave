-- Attest Code Signatures of Enclave Binaries (Mode B Team ID or Mode A cdhash)
SELECT path, signed, identifier, cdhash, authority
FROM signature
WHERE path = '/opt/enterprise/enclave/bin/depot-enclave'
   OR path = '/opt/enterprise/enclave/bin/enclave-apfs-broker'
   OR path = '/Library/Application Support/EnterpriseEnclave/EnclaveCustody.app/Contents/MacOS/enclave-custody-vaultd';
