use bellini::prelude::{CachedRule, IdsKey, IntelCache, Tracer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::fs::File;
use std::path::Path;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Key {
    gid: u64,
    sid: u64,
}

impl Key {
    pub fn as_ids_key(&self) -> IdsKey {
        IdsKey {
            gid: self.gid,
            sid: self.sid,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Rule {
    key: Key,
    rule: String,
    metadata: url::Url,
}

impl AsRef<[u8]> for Rule {
    fn as_ref(&self) -> &[u8] {
        self.rule.as_bytes()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Rules {
    #[serde(rename="rules")]
    inner: Vec<Rule>,
}

impl Rules {
    pub fn from_path<T: AsRef<Path>>(path: T) -> Self {
        let mut f = File::open(path.as_ref()).expect("Could not open path");
        let mut bytes = vec![];
        f.read_to_end(&mut bytes).expect("Failed to read file");
        let rules: Self = serde_json::from_slice(bytes.as_slice()).expect("Failed to parse rules");
        rules
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl Into<IntelCache<Rule>> for Rules {
    fn into(self) -> IntelCache<Rule> {
        let mut map: HashMap<IdsKey, CachedRule<_>> = self.inner.into_iter().map(|r| {
            (r.key.as_ids_key(), CachedRule::Ids(r))
        }).collect();
        map.insert(Tracer::key(), Tracer::rule::<Rule>());
        IntelCache {
            inner: map,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn parse_rules() {
        let _ = env_logger::try_init();
        let rules_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("rules.json");

        let rules = Rules::from_path(rules_path);

        assert_eq!(rules.len(), 1);

        let cache: IntelCache<Rule> = rules.into();

        assert!(cache.inner.get(&IdsKey { gid: 1, sid: 2100498}).is_some());
    }
}