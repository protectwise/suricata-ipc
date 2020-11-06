use crate::intel::{CachedRule, IdsKey};
use crate::eve::{EveMessage, EveEventType};

const TRACER_RULE: &'static str = r#"alert udp 10.1.10.39 54999 -> 75.75.75.75 53 (msg:"Tracer Packet 2"; content:"dannysmagictracerpkt|02|pw"; classtype:attempted-user; gid:1; sid:69041501; rev:1;)"#;
const TRACER_DATA: &'static [u8] = &[
    0xc4u8, 0x04u8, 0x15u8, 0x31u8, 0xd6u8, 0xbbu8, 0xc8u8, 0xe0u8, /* ...1.... */
    0xebu8, 0x17u8, 0xe0u8, 0x07u8, 0x08u8, 0x00u8, 0x45u8, 0x00u8, /* ......E. */
    0x00u8, 0x45u8, 0x68u8, 0x54u8, 0x00u8, 0x00u8, 0x40u8, 0x11u8, /* .EhT..@. */
    0x67u8, 0x96u8, 0x0au8, 0x01u8, 0x0au8, 0x27u8, 0x4bu8, 0x4bu8, /* g....'KK */
    0x4bu8, 0x4bu8, 0xd6u8, 0xd7u8, 0x00u8, 0x35u8, 0x00u8, 0x31u8, /* KK...5.1 */
    0xcau8, 0x77u8, 0xfdu8, 0x96u8, 0x01u8, 0x00u8, 0x00u8, 0x01u8, /* .w...... */
    0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x14u8, 0x64u8, /* .......d */
    0x61u8, 0x6eu8, 0x6eu8, 0x79u8, 0x73u8, 0x6du8, 0x61u8, 0x67u8, /* annysmag */
    0x69u8, 0x63u8, 0x74u8, 0x72u8, 0x61u8, 0x63u8, 0x65u8, 0x72u8, /* ictracer */
    0x70u8, 0x6bu8, 0x74u8, 0x02u8, 0x70u8, 0x77u8, 0x00u8, 0x00u8, /* pkt.pw.. */
    0x01u8, 0x00u8, 0x01u8,
];

pub struct Tracer;

impl Tracer {
    pub fn eve_is_tracer(eve: &EveMessage) -> bool {
        if let EveEventType::Alert(ref alert) = eve.event {
            let key = Self::key();
            return alert.info.gid == key.gid && alert.info.signature_id == key.sid;
        }

        false
    }

    pub fn key() -> IdsKey {
        IdsKey {
            gid: 1,
            sid: 69041501,
        }
    }

    pub fn rule<T>() -> CachedRule<T> {
        CachedRule::Tracer(TRACER_RULE)
    }

    pub fn data() -> &'static [u8] {
        TRACER_DATA
    }
}
