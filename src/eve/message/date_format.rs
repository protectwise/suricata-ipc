use chrono::{DateTime, ParseError, Utc};
use serde::{self, Deserialize, Deserializer, Serializer};

pub const FORMAT: &'static str = "%Y-%m-%dT%H:%M:%S%.f%z";

// The signature of a serialize_with function must follow the pattern:
//
//    fn serialize<S>(&T, S) -> Result<S::Ok, S::Error>
//    where
//        S: Serializer
//
// although it may also be generic over the input types T.
pub fn serialize<S>(date: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let s = format!("{}", date.format(FORMAT));
    serializer.serialize_str(&s)
}

// The signature of a deserialize_with function must follow the pattern:
//
//    fn deserialize<'de, D>(D) -> Result<T, D::Error>
//    where
//        D: Deserializer<'de>
//
// although it may also be generic over the output types T.
pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &'de str = Deserialize::deserialize(deserializer)?;
    parse_date_time(s).map_err(|e| serde::de::Error::custom(e))
}

pub fn parse_date_time(s: &str) -> Result<DateTime<Utc>, ParseError> {
    DateTime::parse_from_str(s, FORMAT).map(|dt| dt.with_timezone(&Utc))
}
