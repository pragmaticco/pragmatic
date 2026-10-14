//! Legal holds (design 4.9).
//!
//! A hold is an object naming a matter and a scope: explicit run ids or a
//! run-id prefix. A run is held while any hold matches it, including runs
//! created after the hold under a held prefix, so holds are matched when a
//! run is about to change, never copied into runs. While held, a run can
//! be neither erased nor touched by retention.
//!
//! Holds live in `<data_dir>/holds.json`, replaced atomically on every
//! change.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use pragmatic::encoding::hex_encode;
use serde::{Deserialize, Serialize};

use crate::fsutil;
use crate::timefmt;

/// What a hold covers: exactly one of `run_ids` and `prefix`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoldScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_ids: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
}

/// One hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hold {
    pub id: String,
    pub matter: String,
    pub scope: HoldScope,
    pub created_at: String,
    /// The token id that placed it.
    pub created_by: String,
}

impl Hold {
    /// True if the hold covers the run.
    pub fn matches(&self, run_id: &str) -> bool {
        if let Some(ids) = &self.scope.run_ids {
            if ids.iter().any(|i| i == run_id) {
                return true;
            }
        }
        matches!(&self.scope.prefix, Some(p) if run_id.starts_with(p.as_str()))
    }
}

/// A request to place a hold.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewHold {
    pub matter: String,
    pub scope: HoldScope,
}

impl NewHold {
    /// Check the request: a matter, and exactly one non-empty scope.
    pub fn check(&self) -> Result<(), String> {
        if self.matter.is_empty()
            || self.matter.len() > 256
            || self.matter.contains(char::is_control)
        {
            return Err("matter: 1 to 256 printable characters".into());
        }
        match (&self.scope.run_ids, &self.scope.prefix) {
            (Some(ids), None) if !ids.is_empty() && ids.len() <= 10_000 => {
                if ids.iter().any(|i| i.is_empty() || i.len() > 200) {
                    return Err("scope.run_ids: each id is 1 to 200 characters".into());
                }
                Ok(())
            }
            (None, Some(p)) if p.len() <= 200 => Ok(()),
            _ => Err("scope: exactly one of run_ids (1 to 10000 ids) or prefix".into()),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HoldsFile {
    holds: Vec<Hold>,
}

/// Every hold, in memory and on disk.
#[derive(Debug)]
pub struct Holds {
    path: PathBuf,
    holds: RwLock<Vec<Hold>>,
}

impl Holds {
    /// `<data_dir>/holds.json`.
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("holds.json")
    }

    pub fn open(data_dir: &Path) -> io::Result<Holds> {
        let path = Holds::path(data_dir);
        let holds = fsutil::read_json::<HoldsFile>(&path)?
            .unwrap_or_default()
            .holds;
        Ok(Holds {
            path,
            holds: RwLock::new(holds),
        })
    }

    /// The ids of every hold that matches the run.
    pub fn matching(&self, run_id: &str) -> Vec<String> {
        self.holds
            .read()
            .expect("holds lock")
            .iter()
            .filter(|h| h.matches(run_id))
            .map(|h| h.id.clone())
            .collect()
    }

    pub fn list(&self) -> Vec<Hold> {
        self.holds.read().expect("holds lock").clone()
    }

    pub fn get(&self, id: &str) -> Option<Hold> {
        self.holds
            .read()
            .expect("holds lock")
            .iter()
            .find(|h| h.id == id)
            .cloned()
    }

    /// A new hold with a fresh id, not yet placed: the server records it in
    /// the erasure ledger before placing it ([`Holds::insert`]).
    pub fn prepare(new: NewHold, created_by: &str) -> io::Result<Hold> {
        let mut id = [0u8; 8];
        pragmatic::rand::fill(&mut id)?;
        Ok(Hold {
            id: format!("hold_{}", hex_encode(&id)),
            matter: new.matter,
            scope: new.scope,
            created_at: timefmt::now_rfc3339(),
            created_by: created_by.to_string(),
        })
    }

    /// Place a prepared hold; it is durable when this returns. Placing a
    /// hold that is already in place (a restore re-applying the ledger)
    /// changes nothing.
    pub fn insert(&self, hold: Hold) -> io::Result<Hold> {
        let mut holds = self.holds.write().expect("holds lock");
        if holds.iter().any(|h| h.id == hold.id) {
            return Ok(hold);
        }
        let mut next = holds.clone();
        next.push(hold.clone());
        fsutil::write_json_atomic(
            &self.path,
            &HoldsFile {
                holds: next.clone(),
            },
        )?;
        *holds = next;
        Ok(hold)
    }

    /// Place a hold; it is durable when this returns.
    pub fn add(&self, new: NewHold, created_by: &str) -> io::Result<Hold> {
        self.insert(Holds::prepare(new, created_by)?)
    }

    /// Remove a hold. `Ok(None)` if there is no such hold.
    pub fn remove(&self, id: &str) -> io::Result<Option<Hold>> {
        let mut holds = self.holds.write().expect("holds lock");
        let Some(i) = holds.iter().position(|h| h.id == id) else {
            return Ok(None);
        };
        let mut next = holds.clone();
        let removed = next.remove(i);
        fsutil::write_json_atomic(
            &self.path,
            &HoldsFile {
                holds: next.clone(),
            },
        )?;
        *holds = next;
        Ok(Some(removed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsutil::testdir::TestDir;

    #[test]
    fn holds_match_ids_and_prefixes_including_later_runs() {
        let d = TestDir::new("holds");
        let h = Holds::open(&d).unwrap();
        let a = h
            .add(
                NewHold {
                    matter: "case-1".into(),
                    scope: HoldScope {
                        run_ids: Some(vec!["r1".into()]),
                        prefix: None,
                    },
                },
                "tok_admin",
            )
            .unwrap();
        let b = h
            .add(
                NewHold {
                    matter: "case-2".into(),
                    scope: HoldScope {
                        run_ids: None,
                        prefix: Some("eu/".into()),
                    },
                },
                "tok_admin",
            )
            .unwrap();
        assert_eq!(h.matching("r1"), vec![a.id.clone()]);
        assert_eq!(h.matching("eu/created-later"), vec![b.id.clone()]);
        assert!(h.matching("us/1").is_empty());
        let h2 = Holds::open(&d).unwrap();
        assert_eq!(h2.list().len(), 2);
        assert_eq!(h2.remove(&a.id).unwrap().unwrap().matter, "case-1");
        assert!(h2.remove(&a.id).unwrap().is_none());
        assert!(Holds::open(&d).unwrap().matching("r1").is_empty());
    }

    #[test]
    fn scopes_are_exactly_one_kind() {
        let both = NewHold {
            matter: "m".into(),
            scope: HoldScope {
                run_ids: Some(vec!["a".into()]),
                prefix: Some("b".into()),
            },
        };
        assert!(both.check().is_err());
        let none = NewHold {
            matter: "m".into(),
            scope: HoldScope {
                run_ids: None,
                prefix: None,
            },
        };
        assert!(none.check().is_err());
        let empty_ids = NewHold {
            matter: "m".into(),
            scope: HoldScope {
                run_ids: Some(vec![]),
                prefix: None,
            },
        };
        assert!(empty_ids.check().is_err());
    }
}
