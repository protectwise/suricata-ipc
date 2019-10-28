use crate::Error;
use serde_json::error::Category;
use serde_json::{Deserializer, Value};

pub struct JsonParser;

impl JsonParser {
    pub fn parse<'a>(buffer: &'a [u8]) -> Result<(&'a [u8], Vec<Vec<u8>>), Error> {
        let deserializer = Deserializer::from_slice(buffer);
        let mut stream_deserializer = deserializer.into_iter::<Value>();
        let mut values = vec![];
        let mut last_good_offset = 0;

        loop {
            match stream_deserializer.next() {
                Some(Ok(_)) => {
                    let slice: Vec<u8> = buffer
                        [last_good_offset..stream_deserializer.byte_offset()]
                        .iter()
                        .cloned()
                        .skip_while(|c| *c == '\n' as u8)
                        .collect();
                    values.push(slice);
                    last_good_offset = stream_deserializer.byte_offset();
                }
                Some(Err(e)) => {
                    if Category::Eof == e.classify() {
                        return Ok((&buffer[last_good_offset..buffer.len()], values));
                    } else {
                        let s = String::from_utf8_lossy(&buffer[last_good_offset..buffer.len()]);
                        log::debug!("Failed to deserialize: {}", s);
                        return Err(Error::SerdeJson(e));
                    }
                }
                None => {
                    return Ok((&buffer[last_good_offset..buffer.len()], values));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use env_logger;

    #[test]
    fn read_single_object() {
        let _ = env_logger::try_init();

        let test = r#"{"thiskey":"is for this object", "fkey": 23.4, "even":{"with":"inner"}}"#;

        let (rem, v) = JsonParser::parse(test.as_ref()).expect("Failed to parse");

        assert!(rem.is_empty());

        assert!(!v.is_empty());

        assert_eq!(v[0], test.to_owned().as_bytes().to_vec());
    }

    #[test]
    fn read_partial_objects() {
        let _ = env_logger::try_init();

        let test = r#"{"key1":"key with a paren set {}","key2":12345}{"another":"part"#;

        let (rem, v) = JsonParser::parse(test.as_ref()).expect("Failed to parse");

        assert!(!rem.is_empty());

        assert_eq!(
            v,
            vec![r#"{"key1":"key with a paren set {}","key2":12345}"#
                .to_owned()
                .as_bytes()
                .to_vec()]
        );
    }

    #[test]
    fn read_multiple_objects() {
        let _ = env_logger::try_init();

        let test =
            r#"{"key1":"key with a paren set {}","key2":12345}{"another":"part being sent"}"#
                .as_ref();

        let (rem, v) = JsonParser::parse(test).expect("Failed to parse");

        assert!(rem.is_empty());

        assert_eq!(
            v,
            vec![
                r#"{"key1":"key with a paren set {}","key2":12345}"#
                    .to_owned()
                    .as_bytes()
                    .to_vec(),
                r#"{"another":"part being sent"}"#.to_owned().as_bytes().to_vec()
            ]
        );
    }
}
