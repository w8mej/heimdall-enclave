-- Verify FileVault Disk Encryption Status
SELECT encrypted, type, name, uuid
FROM disk_encryption
WHERE user_uuid = '' OR name = 'Macintosh HD';
