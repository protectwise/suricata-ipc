use chrono::{TimeZone, Utc};
use prost_types::Timestamp;
use serde::{Deserialize, Deserializer, Serializer};
use std::convert::TryFrom;

/// Serde serialize function that writes timestamps as RFC 3339 strings
pub fn serialize_maybe_timestamp<S>(
    timestamp: &Option<Timestamp>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match timestamp {
        Some(t) => serializer.serialize_str(&Utc.timestamp(t.seconds, t.nanos as u32).to_rfc3339()),
        None => serializer.serialize_str(&""),
    }
}

/// Serde deserialize function that reads optional timestamps from RFC 3339 strings
pub fn deserialize_maybe_timestamp<'de, D>(deserializer: D) -> Result<Option<Timestamp>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<&'de str> = Deserialize::deserialize(deserializer)?;
    let r = if let Some(s) = s {
        let date_time = crate::parse_date_time(s).map_err(|e| serde::de::Error::custom(e))?;
        Some(Timestamp {
            seconds: date_time.timestamp(),
            nanos: i32::try_from(date_time.timestamp_subsec_nanos())
                .map_err(serde::de::Error::custom)?,
        })
    } else {
        None
    };
    Ok(r)
}

/// Serde deserialize function that reads timestamps from RFC 3339 strings
pub fn deserialize_timestamp<'de, D>(deserializer: D) -> Result<Timestamp, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &'de str = Deserialize::deserialize(deserializer)?;
    let date_time = crate::parse_date_time(s).map_err(|e| serde::de::Error::custom(e))?;
    Ok(Timestamp {
        seconds: date_time.timestamp(),
        nanos: i32::try_from(date_time.timestamp_subsec_nanos())
            .map_err(serde::de::Error::custom)?,
    })
}

/// Serde serialize function that writes timestamps as RFC 3339 strings
pub fn serialize_timestamp<S>(timestamp: &Timestamp, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(
        &Utc.timestamp(timestamp.seconds, timestamp.nanos as u32)
            .to_rfc3339(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json;

    #[derive(Debug, Default, PartialEq, serde::Deserialize)]
    struct TimestampTest {
        #[serde(deserialize_with = "deserialize_timestamp")]
        timestamp: Timestamp,
    }

    #[test]
    fn test_timestamp() {
        assert_eq!(
            TimestampTest {
                timestamp: Timestamp {
                    seconds: 1594653526,
                    nanos: 123456789,
                },
            },
            serde_json::from_str::<TimestampTest>(
                r#"{"timestamp":"2020-07-13T15:18:46.123456789+00:00"}"#
            )
            .unwrap(),
        );
    }

    #[test]
    fn test_timestamp_de_error() {
        assert_eq!(
            "premature end of input at line 1 column 18",
            format!(
                "{}",
                &serde_json::from_str::<TimestampTest>(r#"{"timestamp":"00"}"#)
                    .expect_err(&"Expected error")
            )
        );
    }

    #[derive(Debug, Default, PartialEq, serde::Deserialize, serde::Serialize)]
    struct MaybeTimestampTest {
        #[serde(
            default,
            deserialize_with = "deserialize_maybe_timestamp",
            serialize_with = "serialize_maybe_timestamp",
            skip_serializing_if = "Option::is_none"
        )]
        timestamp: Option<Timestamp>,
    }

    #[test]
    fn test_maybe_timestamp_default() {
        check_round_trip(MaybeTimestampTest::default(), r#"{}"#);
    }

    #[test]
    fn test_maybe_timestamp() {
        check_round_trip(
            MaybeTimestampTest {
                timestamp: Some(Timestamp {
                    seconds: 1594653526,
                    nanos: 123456789,
                }),
            },
            r#"{"timestamp":"2020-07-13T15:18:46.123456789+00:00"}"#,
        );
    }

    #[test]
    fn test_maybe_timestamp_de_error() {
        assert_eq!(
            "premature end of input at line 1 column 18",
            format!(
                "{}",
                &serde_json::from_str::<MaybeTimestampTest>(r#"{"timestamp":"00"}"#)
                    .expect_err(&"Expected error")
            )
        );
    }

    fn check_round_trip<
        T: std::fmt::Debug + PartialEq + serde::de::DeserializeOwned + serde::ser::Serialize,
    >(
        orig: T,
        expected_str: &str,
    ) {
        let to_string = serde_json::to_string(&orig).unwrap();
        assert_eq!(&expected_str, &to_string);
        let from_string = serde_json::from_str(&to_string).unwrap();
        assert_eq!(&orig, &from_string);
    }
}
