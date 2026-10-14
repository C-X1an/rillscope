//! Shared preflight and duplicate-preserving rejection before typed deserialization.
use crate::error::{ErrorCode as E, Result};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use std::fmt;

pub(crate) fn preflight(bytes: &[u8], max_bytes: usize, max_depth: usize) -> Result<()> {
    if bytes.len() > max_bytes {
        return Err(E::Limit.into());
    }
    std::str::from_utf8(bytes).map_err(|_| E::Input)?;
    let (mut quoted, mut escaped, mut depth) = (false, false, 0usize);
    for b in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if *b == b'\\' {
                escaped = true;
            } else if *b == b'"' {
                quoted = false;
            }
        } else {
            match b {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth = depth.checked_add(1).ok_or(E::Limit)?;
                    if depth > max_depth {
                        return Err(E::Limit.into());
                    }
                }
                b'}' | b']' => depth = depth.checked_sub(1).ok_or(E::Input)?,
                _ => {}
            }
        }
    }
    if quoted || depth != 0 {
        return Err(E::Input.into());
    }
    Ok(())
}

struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("closed JSON")
            }
            fn visit_bool<X: de::Error>(self, b: bool) -> std::result::Result<Strict, X> {
                Ok(Strict(b.into()))
            }
            fn visit_i64<X: de::Error>(self, n: i64) -> std::result::Result<Strict, X> {
                Ok(Strict(n.into()))
            }
            fn visit_u64<X: de::Error>(self, n: u64) -> std::result::Result<Strict, X> {
                Ok(Strict(n.into()))
            }
            fn visit_f64<X: de::Error>(self, _: f64) -> std::result::Result<Strict, X> {
                Err(X::custom("unsupported number"))
            }
            fn visit_str<X: de::Error>(self, s: &str) -> std::result::Result<Strict, X> {
                Ok(Strict(s.into()))
            }
            fn visit_string<X: de::Error>(self, s: String) -> std::result::Result<Strict, X> {
                Ok(Strict(s.into()))
            }
            fn visit_unit<X: de::Error>(self) -> std::result::Result<Strict, X> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut out = Vec::new();
                while let Some(Strict(value)) = seq.next_element()? {
                    out.try_reserve(1)
                        .map_err(|_| de::Error::custom("allocation limit"))?;
                    out.push(value);
                }
                Ok(Strict(Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut out = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if out.contains_key(&key) {
                        return Err(de::Error::custom("duplicate key"));
                    }
                    let Strict(value) = map.next_value()?;
                    out.insert(key, value);
                }
                Ok(Strict(Value::Object(out)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}
pub(crate) fn strict_json(bytes: &[u8], max_bytes: usize, max_depth: usize) -> Result<Value> {
    preflight(bytes, max_bytes, max_depth)?;
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let Strict(value) = Strict::deserialize(&mut deserializer).map_err(|_| E::Input)?;
    deserializer.end().map_err(|_| E::Input)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_decoded_keys_and_excess_depth_reject() {
        assert!(strict_json(br#"{"version":1,"\u0076ersion":1}"#, 100, 10).is_err());
        assert_eq!(
            strict_json(b"[[[0]]]", 100, 2).map_err(|e| e.code),
            Err(E::Limit)
        );
        assert!(strict_json(b"{\"x\":1.0}", 100, 10).is_err());
        assert!(strict_json(b"{} {}", 100, 10).is_err());
    }
}
