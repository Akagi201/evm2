//! Read-set recording for database warm-up passes.

use super::db::{DbResult, DynDatabase};
use crate::{bytecode::Bytecode, evm::state::AccountInfo, interpreter::Word};
use alloy_primitives::{
    Address, B256,
    map::{AddressMap, AddressSet, B256Set, HashSet, U256Set},
};

/// Database reads recorded by [`MissRecorder`]: the state a warm-up pass would prefetch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReadSet {
    /// Accounts whose info was read.
    pub accounts: AddressSet,
    /// Storage slots read, keyed by address.
    pub storage: AddressMap<HashSet<Word>>,
    /// Bytecode hashes the backing database was asked for.
    pub code_hashes: B256Set,
    /// Block numbers the backing database was asked for.
    pub block_hashes: U256Set,
}

/// Database wrapper that records the reads that reach the backing database.
///
/// Wrap the backing database with this *inside* the execution cache: reads the cache serves never
/// reach the wrapper, so the recorded [`ReadSet`] is exactly the state the cache could not serve.
/// A warm-up loop runs one pass with the recorder, batch-prefetches the recorded reads, and
/// re-runs against a warm database.
///
/// Reads are recorded before they are served, so a read that fails still appears in the set.
#[derive(Clone, Debug, Default)]
pub struct MissRecorder<D> {
    db: D,
    read_set: ReadSet,
}

impl<D> MissRecorder<D> {
    /// Creates a recorder around `db`.
    #[inline]
    pub fn new(db: D) -> Self {
        Self { db, read_set: ReadSet::default() }
    }

    /// Returns the reads recorded so far.
    #[inline]
    pub const fn read_set(&self) -> &ReadSet {
        &self.read_set
    }

    /// Takes the reads recorded so far, leaving the recorder and the database in place for the
    /// next pass.
    #[inline]
    pub fn take_read_set(&mut self) -> ReadSet {
        core::mem::take(&mut self.read_set)
    }

    /// Consumes the recorder and returns the database together with the recorded reads.
    #[inline]
    pub fn into_parts(self) -> (D, ReadSet) {
        (self.db, self.read_set)
    }

    /// Returns the wrapped database.
    #[inline]
    pub const fn inner(&self) -> &D {
        &self.db
    }

    /// Returns the wrapped database mutably.
    #[inline]
    pub const fn inner_mut(&mut self) -> &mut D {
        &mut self.db
    }
}

impl<D: DynDatabase> DynDatabase for MissRecorder<D> {
    #[inline]
    fn get_account(&mut self, address: &Address) -> DbResult<Option<AccountInfo>> {
        self.read_set.accounts.insert(*address);
        self.db.get_account(address)
    }

    #[inline]
    fn get_code_by_hash(&mut self, code_hash: &B256) -> DbResult<Bytecode> {
        self.read_set.code_hashes.insert(*code_hash);
        self.db.get_code_by_hash(code_hash)
    }

    #[inline]
    fn get_storage(&mut self, address: &Address, key: &Word) -> DbResult<Word> {
        self.read_set.storage.entry(*address).or_default().insert(*key);
        self.db.get_storage(address, key)
    }

    #[inline]
    fn get_block_hash(&mut self, number: &Word) -> DbResult<B256> {
        self.read_set.block_hashes.insert(*number);
        self.db.get_block_hash(number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::db::{CacheDB, Db, EmptyDB, InMemoryDB};

    const ACCOUNT: Address = Address::with_last_byte(0xaa);
    const OTHER_ACCOUNT: Address = Address::with_last_byte(0xbb);
    const SLOT: Word = Word::from_limbs([3, 0, 0, 0]);
    const OTHER_SLOT: Word = Word::from_limbs([4, 0, 0, 0]);

    #[test]
    fn records_every_read_category_once() {
        let mut recorder = MissRecorder::new(Db::new(EmptyDB::default()));

        // Repeating a read records it once.
        for _ in 0..2 {
            DynDatabase::get_account(&mut recorder, &ACCOUNT).unwrap();
            DynDatabase::get_account(&mut recorder, &OTHER_ACCOUNT).unwrap();
            DynDatabase::get_storage(&mut recorder, &ACCOUNT, &SLOT).unwrap();
            DynDatabase::get_storage(&mut recorder, &ACCOUNT, &OTHER_SLOT).unwrap();
            DynDatabase::get_code_by_hash(&mut recorder, &B256::repeat_byte(1)).unwrap();
            DynDatabase::get_block_hash(&mut recorder, &Word::from(9)).unwrap();
        }

        let read_set = recorder.read_set();
        assert_eq!(read_set.accounts.len(), 2);
        assert_eq!(read_set.storage.len(), 1);
        assert_eq!(read_set.storage[&ACCOUNT].len(), 2);
        assert_eq!(read_set.code_hashes.len(), 1);
        assert_eq!(read_set.block_hashes.len(), 1);
    }

    #[test]
    fn reads_served_by_the_cache_do_not_reach_the_recorder() {
        let mut inner = InMemoryDB::default();
        inner.insert_account_info(&ACCOUNT, AccountInfo::default().with_balance(Word::from(5)));
        let mut cache = CacheDB::new(MissRecorder::new(inner));

        let first = DynDatabase::get_account(&mut cache, &ACCOUNT).unwrap();
        let second = DynDatabase::get_account(&mut cache, &ACCOUNT).unwrap();
        assert_eq!(first.expect("account exists").balance, Word::from(5));
        assert_eq!(second.expect("account exists").balance, Word::from(5));

        // Only the read that missed the outer cache reached the recorder.
        assert_eq!(cache.db.read_set().accounts.len(), 1);
    }

    #[test]
    fn take_read_set_keeps_the_recorder_usable() {
        let mut recorder = MissRecorder::new(Db::new(EmptyDB::default()));
        DynDatabase::get_account(&mut recorder, &ACCOUNT).unwrap();
        assert_eq!(recorder.take_read_set().accounts.len(), 1);

        // The recorder keeps recording for the next pass.
        DynDatabase::get_account(&mut recorder, &OTHER_ACCOUNT).unwrap();
        assert_eq!(recorder.take_read_set().accounts.len(), 1);

        DynDatabase::get_account(&mut recorder, &OTHER_ACCOUNT).unwrap();
        let (db, read_set) = recorder.into_parts();
        assert_eq!(read_set.accounts.len(), 1);
        assert!(read_set.accounts.contains(&OTHER_ACCOUNT));
        let _ = db;
    }

    #[test]
    fn read_set_warms_a_second_pass() {
        // Pass one discovers the read set against a cold database.
        let mut cold = InMemoryDB::default();
        cold.insert_account_info(&ACCOUNT, AccountInfo::default().with_balance(Word::from(5)));
        cold.insert_account_storage(&ACCOUNT, &SLOT, &Word::from(7));
        let mut cache = CacheDB::new(MissRecorder::new(cold));

        DynDatabase::get_account(&mut cache, &ACCOUNT).unwrap();
        DynDatabase::get_storage(&mut cache, &ACCOUNT, &SLOT).unwrap();
        let read_set = cache.db.take_read_set();

        // Prefetch the recorded reads into a warm database.
        let mut warm = InMemoryDB::default();
        for account in &read_set.accounts {
            warm.insert_account_info(account, AccountInfo::default().with_balance(Word::from(5)));
            for slot in &read_set.storage[account] {
                warm.insert_account_storage(account, slot, &Word::from(7));
            }
        }

        // Pass two replays against the warm database.
        let mut replay = CacheDB::new(warm);
        let account =
            DynDatabase::get_account(&mut replay, &ACCOUNT).unwrap().expect("account exists");
        assert_eq!(account.balance, Word::from(5));
        assert_eq!(DynDatabase::get_storage(&mut replay, &ACCOUNT, &SLOT).unwrap(), Word::from(7));
    }
}
