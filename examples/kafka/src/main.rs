//! # Kafka Example
//! Example of reading packets from a file, passing them to suricata via bellini, and receiving
//! alerts. Alerts are then published on kafka
mod kafka;
mod packet;

use bellini::prelude::*;
use futures::StreamExt;
use log::*;

#[tokio::main]
async fn main() {
    let _ = env_logger::try_init();

    let producer = kafka::Producer::new();

    let resources = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().expect("Invalid path")
        .parent().expect("Invalid path")
        .join("resources");
    let config = Config::default();
    let rules = Rules::from_path(resources.join("test.rules")).expect("Could not parse rules");
    let cache: IntelCache<Rule> = rules.into();
    cache.materialize_rules(config.rule_path.clone()).expect("Failed to materialize rules");

    let mut ids = Ids::new(config).await.expect("Failed to create ids");
    let mut ids_alerts = ids.take_alerts().expect("No alerts");

    tokio::spawn(packet::send_packets(ids));

    while let Some(try_alert) = ids_alerts.next().await {
        let alerts = try_alert.expect("Failed to receive alert");
        for try_alert in alerts {
            let alert = try_alert.expect("Could not parse alert");
            let sid = alert.alert.signature_id;
            let gid = alert.alert.gid;
            if let Some(intel) = cache.observed(alert) {
                if let Observed::Alert { rule, message } = intel {
                    info!("Rule={:?}   Message={:?}", rule, message);
                    let produced = producer.produce(message).await;
                    info!("Produced as {:?}", produced);
                }
            } else {
                warn!("Failed to find rule. Gid={}   Sid={}", gid, sid)
            }
        }
    }
}