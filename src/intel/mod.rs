mod rules;
mod tracer;

pub use rules::{Rule, Rules};
pub use tracer::Tracer;

use crate::errors::Error;

use chrono::DateTime;
use chrono::Utc;
use log::info;
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct IdsKey {
    pub gid: u64,
    pub sid: u64,
}

pub enum CachedRule<T> {
    Ids(T),
    Tracer(&'static str),
}

impl<T> CachedRule<T> {
    pub fn rule_bytes(&self) -> &[u8]
    where
        T: AsRef<[u8]>,
    {
        match self {
            CachedRule::Ids(i) => i.as_ref(),
            CachedRule::Tracer(s) => s.as_bytes(),
        }
    }

    pub fn observed<M>(&self, msg: M, ts: DateTime<Utc>) -> Observed<T, M>
    where
        T: Clone,
    {
        match self {
            CachedRule::Ids(r) => Observed::Alert {
                rule: r.clone(),
                ts: ts,
                message: msg,
            },
            CachedRule::Tracer(_) => Observed::Tracer(ts),
        }
    }
}

pub enum Observed<T, M> {
    Alert {
        rule: T,
        ts: DateTime<Utc>,
        message: M,
    },
    Tracer(DateTime<Utc>),
}

pub struct IntelCache<T> {
    pub inner: HashMap<IdsKey, CachedRule<T>>,
}

const LINE_SEPARATOR: &'static [u8] = &['\n' as _];

pub trait Observable {
    fn timestamp(&self) -> DateTime<Utc>;
    fn key(&self) -> Option<IdsKey>;
}

impl<T> IntelCache<T> {
    pub fn observed<M>(&self, msg: M) -> Option<Observed<T, M>>
    where
        T: Clone,
        M: Observable,
    {
        msg.key().and_then(|k| {
            let ts = msg.timestamp();
            self.inner.get(&k).map(|r| r.observed(msg, ts))
        })
    }

    pub fn materialize_rules<P: AsRef<Path>>(&self, path: P) -> Result<(), Error>
    where
        T: AsRef<[u8]>,
    {
        let p: &Path = path.as_ref();
        let mut f = std::fs::File::create(p).map_err(Error::from)?;
        for kv in self.inner.iter() {
            let (_, rule) = kv;
            f.write(rule.rule_bytes()).map_err(Error::from)?;
            f.write(LINE_SEPARATOR).map_err(Error::from)?;
        }
        f.flush().map_err(Error::Io)?;
        info!("Materialized rules to {:?}", p);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<T> Default for IntelCache<T> {
    fn default() -> Self {
        IntelCache {
            inner: HashMap::default(),
        }
    }
}
