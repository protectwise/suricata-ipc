# suricata-rs

Library to enable packet sharing with suricata, and reading alerts from an eve
socket. Alerts read can then use an intel cache to determine additional metadata
about them.

```rust
#[tokio::main]
async fn main() {
    let rules = Rules::from_path("my.rules").expect("Failed to parse rules");
    let config = Config::default();
    let rules = Rules::from_path(resources.join("test.rules")).expect("Could not parse rules");
    let cache: IntelCache<Rule> = rules.into();
    cache.materialize_rules(config.rule_path.clone()).expect("Failed to materialize rules");

    let mut ids = Ids::new(config).await.expect("Failed to create ids");
    let ids_alerts = ids.take_alerts().expect("No alerts");

    send_packets(&mut ids).await.expect("Failed to send packets");

    let alerts: Result<Vec<_>, Error> = ids_alerts.try_collect().await;
    let alerts: Result<Vec<_>, Error> = alerts.expect("Failed to receive alerts")
        .into_iter().flat_map(|v| v).collect();
    let alerts = alerts.expect("Failed to parse alerts");

    for eve in alerts {
        println!("Eve={:?}", eve);
        if let Some(intel) = cache.observed(eve) {
            if let Observed::Alert { rule, message: _ } = intel {
                println!("Rule={:?}", rule);
            }
        }
    }
}
```

## Develop With Docker
Install [lefthook](https://github.com/Arkweid/lefthook/blob/master/docs/full_guide.md). You can then run

    lefthook run develop

## Cloning
This repository uses submodules, so should be cloned with

    git clone --recurse-submodules -j8 git@github.com:OISF/suricata-verify.git
      
If you've already cloned, you'll need to update the submodules

    git submodule update --init --recursive
 