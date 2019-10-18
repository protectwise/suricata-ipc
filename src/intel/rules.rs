use crate::Error;
use crate::intel::{IdsKey, IntelCache, CachedRule, Tracer};

use lazy_static::lazy_static;
use log::*;
use regex::Regex;
use std::fs::File;
use std::path::Path;
use std::io::{BufRead, BufReader};
use std::str::FromStr;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct Rule {
    key: IdsKey,
    rule: String,
}

impl AsRef<[u8]> for Rule {
    fn as_ref(&self) -> &[u8] {
        self.rule.as_bytes()
    }
}

lazy_static! {
    pub static ref SID_REGEX: Regex = Regex::from_str(r#".+sid\:\s*(\d+);.+"#).expect("Bad regex");
    pub static ref GID_REGEX: Regex = Regex::from_str(r#".+gid\:\s*(\d+);.+"#).expect("Bad regex");
}

fn parse_rule(line: &str) -> Result<Rule, Error> {
    let caps = SID_REGEX.captures(line).ok_or(Error::Custom { msg: format!("No sid: {}", line) })?;
    let sid = caps.get(0).ok_or(Error::Custom { msg: format!("No sid: {}", line) })?;
    let sid = u64::from_str(sid.as_str()).map_err(Error::ParseInt)?;
    let gid = if let Some(gid) = GID_REGEX.captures(line) {
        u64::from_str(&gid[0]).map_err(Error::ParseInt)?
    } else {
        1
    };
    Ok(Rule {
        key: IdsKey {
            gid: gid,
            sid: sid
        },
        rule: line.to_owned(),
    })
}

pub struct Rules {
    inner: Vec<Rule>,
}

impl Rules {
    pub fn from_path<T: AsRef<Path>>(path: T) -> Result<Self, Error> {
        let f = File::open(path.as_ref()).map_err(Error::Io)?;
        let lines: Result<Vec<_>, Error> = BufReader::new(f)
            .lines()
            .map(|r| {
                r.map_err(Error::Io)
            })
            .collect();
        let lines = lines?;
        let rules: Vec<_> = lines.into_iter().flat_map(|l| {
            match parse_rule(&l) {
                Ok(r) => Some(r),
                Err(e) => {
                    warn!("Failed to parse rule '{}': {:?}", l, e);
                    None
                }
            }
        }).collect();
        Ok(Self { inner: rules })
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl Into<IntelCache<Rule>> for Rules {
    fn into(self) -> IntelCache<Rule> {
        let mut map: HashMap<IdsKey, CachedRule<Rule>> = self.inner.into_iter().map(|r| {
            (r.key.clone(), CachedRule::Ids(r))
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
        let rules_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("test.rules");

        let rules = Rules::from_path(rules_path).expect("Failed to get rules");

        assert_eq!(rules.len(), 10);

        let cache: IntelCache<Rule> = rules.into();

        assert!(cache.inner.get(&IdsKey { gid: 1, sid: 1}).is_some());
        assert!(cache.inner.get(&IdsKey { gid: 1, sid: 2}).is_some());
    }
}