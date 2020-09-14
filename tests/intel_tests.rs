use std::path::PathBuf;
use suricata_ipc::prelude::*;

#[derive(Clone, Default)]
struct LogIntercept {
    saw_record: std::sync::Arc<std::sync::atomic::AtomicBool>,
    saw_warning: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl log::Log for LogIntercept {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        self.saw_record
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let s = record.args().to_string();
        if s.contains("Failed to parse rule '#'") {
            self.saw_warning
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Flushes any buffered records.
    fn flush(&self) {}
}

#[test]
fn parse_rules() {
    let logger = Box::new(LogIntercept::default());

    log::set_boxed_logger(logger.clone()).unwrap();
    log::set_max_level(log::LevelFilter::Debug);

    let rules_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("resources")
        .join("test.rules");

    log::info!("Checking logger");

    let rules = Rules::from_path(rules_path).expect("Failed to get rules");

    assert_eq!(rules.len(), 20);

    let cache: IntelCache<Rule> = rules.into();

    assert!(cache
        .inner
        .get(&IdsKey {
            gid: 1,
            sid: 3003002
        })
        .is_some());
    assert!(cache
        .inner
        .get(&IdsKey {
            gid: 1,
            sid: 3016009
        })
        .is_some());

    assert!(logger.saw_record.load(std::sync::atomic::Ordering::Relaxed));
    assert!(!logger
        .saw_warning
        .load(std::sync::atomic::Ordering::Relaxed));
}
