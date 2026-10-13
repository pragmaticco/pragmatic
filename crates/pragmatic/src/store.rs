//! `JournalStore` - where a runtime keeps its journals and channel inboxes.
//!
//! Shared by the sync [`Runtime`](crate::Runtime) and the async
//! [`AsyncRuntime`](crate::AsyncRuntime): journal loading/creation (memory or
//! one append-only file per run), HMAC keying, dangling-intent recovery, and
//! single-process channel delivery.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};

use crate::fault::Fault;
use crate::journal_v1::{Event, Journal};
use crate::value::Value;

/// How a dangling effect intent (a crash inside the write-ahead window) is
/// resolved on resume.
pub enum Recover {
    /// The effect is idempotent or known to have completed: close the intent
    /// with this committed result. Replay will reuse it without touching the
    /// world again.
    Commit(Value),
    /// Undo / write off the effect. The resumed run will perform it fresh.
    Compensate,
}

enum Storage {
    Memory,
    Dir(PathBuf),
}

pub(crate) struct JournalStore {
    storage: Storage,
    key: Option<Vec<u8>>,
    /// Loaded journals by run id. In `Dir` mode this is a write-through
    /// cache over the journal files.
    journals: HashMap<String, Journal>,
    /// Per-run channel inboxes (single-process delivery; receives are
    /// journaled, so replay does not need the inbox).
    inboxes: HashMap<String, HashMap<String, VecDeque<Value>>>,
}

impl JournalStore {
    pub fn in_memory() -> Self {
        JournalStore {
            storage: Storage::Memory,
            key: None,
            journals: HashMap::new(),
            inboxes: HashMap::new(),
        }
    }

    pub fn on_dir(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(JournalStore {
            storage: Storage::Dir(dir),
            key: None,
            journals: HashMap::new(),
            inboxes: HashMap::new(),
        })
    }

    pub fn set_key(&mut self, key: &[u8]) {
        self.key = Some(key.to_vec());
    }

    fn path_for(dir: &Path, run_id: &str) -> PathBuf {
        // Run ids become filenames; keep them filesystem-safe.
        let safe: String = run_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        dir.join(format!("{safe}.journal"))
    }

    /// Ensure the journal for `run_id` is loaded (creating it if `create`),
    /// and return it.
    pub fn load(&mut self, run_id: &str, create: bool) -> Result<&mut Journal, Fault> {
        if !self.journals.contains_key(run_id) {
            let journal = match &self.storage {
                Storage::Memory => {
                    if !create {
                        return Err(Fault::Io(format!("no journal for run '{run_id}'")));
                    }
                    match &self.key {
                        Some(k) => Journal::in_memory_keyed(k),
                        None => Journal::in_memory(),
                    }
                }
                Storage::Dir(dir) => {
                    let path = Self::path_for(dir, run_id);
                    if path.exists() {
                        let loaded = match &self.key {
                            Some(k) => Journal::open_keyed(&path, k)?,
                            None => Journal::open(&path)?,
                        };
                        loaded.journal
                    } else if create {
                        match &self.key {
                            Some(k) => Journal::create_keyed(&path, k)?,
                            None => Journal::create(&path)?,
                        }
                    } else {
                        return Err(Fault::Io(format!("no journal for run '{run_id}'")));
                    }
                }
            };
            self.journals.insert(run_id.to_string(), journal);
        }
        Ok(self.journals.get_mut(run_id).expect("inserted above"))
    }

    /// The journal and inbox for `run_id`, both mutably (the shape `execute`
    /// needs). Journal must already be loaded.
    pub fn parts(&mut self, run_id: &str) -> (&mut Journal, &mut HashMap<String, VecDeque<Value>>) {
        let journal = self
            .journals
            .get_mut(run_id)
            .expect("journal loaded by caller");
        let inbox = self.inboxes.entry(run_id.to_string()).or_default();
        (journal, inbox)
    }

    /// No-orphaned-effect: close every dangling intent per `recovery` before
    /// a resume re-enters the program ([Eff-recover]).
    pub fn recover_dangling(
        &mut self,
        run_id: &str,
        recovery: &mut dyn FnMut(&str, &Value) -> Recover,
    ) -> Result<(), Fault> {
        let journal = self.load(run_id, false)?;
        let dangling = journal.dangling_intents();
        for (cursor, name) in dangling {
            let arg = match &journal.get(cursor).expect("cursor valid").event {
                Event::EffectIntent { arg, .. } => arg.clone(),
                _ => unreachable!("dangling_intents returns intent cursors"),
            };
            match recovery(&name, &arg) {
                Recover::Commit(result) => {
                    journal.append(Event::EffectCommit { name, result })?;
                }
                Recover::Compensate => {
                    journal.append(Event::EffectCompensated { name })?;
                }
            }
        }
        journal.sync()?;
        Ok(())
    }

    pub fn send(&mut self, run_id: &str, channel: &str, value: Value) {
        self.inboxes
            .entry(run_id.to_string())
            .or_default()
            .entry(channel.to_string())
            .or_default()
            .push_back(value);
    }

    pub fn evict(&mut self, run_id: &str) {
        self.journals.remove(run_id);
    }
}
