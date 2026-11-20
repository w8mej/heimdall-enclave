//! Durable, bounded replay consumption. State is committed before tool side effects.
use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::{fs::OpenOptions, path::Path};

const USED: TableDefinition<&str, u64> = TableDefinition::new("consumed_v2");
const META: TableDefinition<u8, u64> = TableDefinition::new("metadata_v2");
const MAX_CAPACITY: u64 = 65_536;
fn storage(e: impl std::fmt::Display) -> enclave_core::error::EnclaveError {
    err!(EIO, "TICKET_REPLAY_STORE", "{e}")
}
/// Durable replay state in a daemon-owned 0700 directory. Opening a missing,
/// corrupt or already-locked database fails closed. Do not delete/reinitialize
/// it while any ticket signed by the current issuer key can remain valid.
#[derive(Debug)]
pub struct TicketReplayFilter {
    db: Database,
}
impl TicketReplayFilter {
    fn file(path: &Path, create: bool) -> EnclaveResult<std::fs::File> {
        let parent = path.parent().ok_or_else(|| err!(EINVAL, "REPLAY_PATH"))?;
        if !path.is_absolute() || std::fs::canonicalize(parent).map_err(storage)? != parent {
            fail!(EACCES, "REPLAY_DIRECTORY_UNTRUSTED");
        }
        let meta = std::fs::metadata(parent).map_err(storage)?;
        // SAFETY: geteuid has no preconditions and observes current process identity.
        let uid = unsafe { libc::geteuid() };
        if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
            fail!(EACCES, "REPLAY_DIRECTORY_UNTRUSTED");
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(create)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(storage)?;
        let meta = file.metadata().map_err(storage)?;
        if !meta.is_file()
            || meta.uid() != uid
            || meta.mode() & 0o077 != 0
            || meta.nlink() != 1
            || (!create && meta.len() == 0)
        {
            fail!(EACCES, "REPLAY_FILE_UNTRUSTED");
        }
        Ok(file)
    }
    /// Trusted first-time provisioning only; refuses an existing path.
    pub fn initialize(path: &Path, capacity: u64) -> EnclaveResult<Self> {
        if capacity == 0 || capacity > MAX_CAPACITY {
            fail!(EINVAL, "REPLAY_CAPACITY_INVALID");
        }
        let db = Database::builder()
            .create_file(Self::file(path, true)?)
            .map_err(storage)?;
        let tx = db.begin_write().map_err(storage)?;
        {
            let mut meta = tx.open_table(META).map_err(storage)?;
            meta.insert(0, capacity).map_err(storage)?;
            meta.insert(1, 0).map_err(storage)?;
            tx.open_table(USED).map_err(storage)?;
        }
        tx.commit().map_err(storage)?;
        // Persist the directory entry as well as the database contents.
        std::fs::File::open(path.parent().unwrap())
            .map_err(storage)?
            .sync_all()
            .map_err(storage)?;
        Ok(Self { db })
    }
    /// Reopen provisioned state. No automatic reset/recreation on any error.
    pub fn open(path: &Path) -> EnclaveResult<Self> {
        let db = Database::builder()
            .create_file(Self::file(path, false)?)
            .map_err(storage)?;
        {
            let tx = db.begin_read().map_err(storage)?;
            let meta = tx.open_table(META).map_err(storage)?;
            let capacity = meta
                .get(0)
                .map_err(storage)?
                .ok_or_else(|| storage("capacity missing"))?
                .value();
            if capacity == 0 || capacity > MAX_CAPACITY || meta.get(1).map_err(storage)?.is_none() {
                fail!(EIO, "TICKET_REPLAY_STORE");
            }
            tx.open_table(USED).map_err(storage)?;
        }
        Ok(Self { db })
    }
    /// Atomically persist consumption with immediate fsync durability. The daemon
    /// supplies trusted UNIX time, not a request timestamp. Clock rollback fails.
    pub fn consume(&self, id: &str, expires: u64, now: u64) -> EnclaveResult<()> {
        if id.is_empty() || id.len() > 256 || expires < now {
            fail!(EINVAL, "REPLAY_INPUT_INVALID");
        }
        let tx = self.db.begin_write().map_err(storage)?;
        {
            let mut meta = tx.open_table(META).map_err(storage)?;
            let last = meta
                .get(1)
                .map_err(storage)?
                .ok_or_else(|| storage("clock missing"))?
                .value();
            let cap = meta
                .get(0)
                .map_err(storage)?
                .ok_or_else(|| storage("capacity missing"))?
                .value();
            if now < last {
                fail!(EACCES, "TICKET_CLOCK_ROLLBACK");
            }
            let mut used = tx.open_table(USED).map_err(storage)?;
            let mut expired = Vec::new();
            for row in used.iter().map_err(storage)? {
                let (id, expiry) = row.map_err(storage)?;
                if expiry.value() < now {
                    expired.push(id.value().to_owned());
                }
            }
            for id in expired {
                used.remove(id.as_str()).map_err(storage)?;
            }
            if used.get(id).map_err(storage)?.is_some() {
                fail!(EACCES, "TICKET_REPLAYED");
            }
            if used.len().map_err(storage)? >= cap {
                fail!(E2BIG, "TICKET_REPLAY_CAPACITY");
            }
            used.insert(id, expires).map_err(storage)?;
            meta.insert(1, now).map_err(storage)?;
        }
        tx.commit().map_err(storage)?;
        Ok(())
    }
}
