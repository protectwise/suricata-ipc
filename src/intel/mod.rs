mod tracer;

pub use tracer::Tracer;

use crate::errors::Error;
use crate::eve::{Message as EveMessage, Message};

use chrono::DateTime;
use chrono::Utc;
use log::info;
use parser::*;
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

#[derive(Eq, Hash, PartialEq)]
pub struct IdsKey {
    pub gid: u64,
    pub sid: u64,
}

pub enum CachedRule<T> {
    Ids(T),
    Tracer(&'static str),
}

impl CachedRule<T> {
    pub fn rule_bytes(&self) -> &[u8]
        where T: AsRef<[u8]>
    {
        match self {
            CachedRule::Ids(i) => i.intel.rule.as_ref(),
            CachedRule::Tracer(s) => s.as_bytes(),
        }
    }

    pub fn observed(&self, msg: EveMessage) -> Observed {
        match self {
            CachedRule::Ids(r) => Scored::Alert(msg),
            CachedRule::Tracer(_) => Scored::Tracer(msg.timestamp),
        }
    }
}

pub enum Observed {
    Alert(EveMessage),
    Tracer(DateTime<Utc>),
}

pub struct IntelCache<T> {
    pub inner: HashMap<IdsKey, CachedRule<T>>,
}

const LINE_SEPARATOR: &'static [u8] = &['\n' as _];

impl<T> IntelCache<T> {
    pub fn materialize_rules<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let p: &Path = path.as_ref();
        let mut f = std::fs::File::create(p).map_err(Error::Io)?;
        for kv in self.inner.iter() {
            let (_, rule) = kv;
            f.write(rule.rule_bytes()).map_err(Error::Io)?;
            f.write(LINE_SEPARATOR).map_err(Error::Io)?;
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
