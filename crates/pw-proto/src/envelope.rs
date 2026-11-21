// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Wire envelope version (the `v` field). Independent of the protocol major/minor.
pub const ENVELOPE_VERSION: u8 = 1;

/// Largest frame (the JSON body, not counting the 4-byte length prefix) either side accepts.
pub const MAX_FRAME_BYTES: u32 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Req,
    Res,
    Event,
    Err,
}

/// `{ v, id?, kind, method | topic, payload }`
///
/// * `req`   — `id` and `method` set.
/// * `res`   — `id` of the request it answers.
/// * `err`   — `id` of the failed request when known; payload is an [`crate::ErrorPayload`].
/// * `event` — `topic` set, no `id`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct Envelope {
    pub v: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(type = "number", optional))]
    pub id: Option<u64>,
    pub kind: Kind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub topic: Option<String>,
    #[serde(default)]
    #[cfg_attr(feature = "ts-export", ts(type = "unknown"))]
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShapeError {
    #[error("unsupported envelope version {0}")]
    UnsupportedVersion(u8),
    #[error("{0:?} envelope is missing `{1}`")]
    Missing(Kind, &'static str),
    #[error("{0:?} envelope must not carry `{1}`")]
    Unexpected(Kind, &'static str),
}

impl Envelope {
    fn new(kind: Kind, id: Option<u64>, payload: serde_json::Value) -> Self {
        Self {
            v: ENVELOPE_VERSION,
            id,
            kind,
            method: None,
            topic: None,
            payload,
        }
    }

    pub fn request<T: Serialize>(
        id: u64,
        method: &str,
        payload: &T,
    ) -> Result<Self, serde_json::Error> {
        let mut env = Self::new(Kind::Req, Some(id), serde_json::to_value(payload)?);
        env.method = Some(method.to_owned());
        Ok(env)
    }

    pub fn response<T: Serialize>(id: u64, payload: &T) -> Result<Self, serde_json::Error> {
        Ok(Self::new(
            Kind::Res,
            Some(id),
            serde_json::to_value(payload)?,
        ))
    }

    pub fn event<T: Serialize>(topic: &str, payload: &T) -> Result<Self, serde_json::Error> {
        let mut env = Self::new(Kind::Event, None, serde_json::to_value(payload)?);
        env.topic = Some(topic.to_owned());
        Ok(env)
    }

    pub fn error(
        id: Option<u64>,
        payload: &crate::ErrorPayload,
    ) -> Result<Self, serde_json::Error> {
        Ok(Self::new(Kind::Err, id, serde_json::to_value(payload)?))
    }

    /// Decodes the payload into a typed value.
    pub fn payload_as<T: DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        T::deserialize(&self.payload)
    }

    /// Checks the envelope version and that the fields required by `kind` are present.
    pub fn check_shape(&self) -> Result<(), ShapeError> {
        if self.v != ENVELOPE_VERSION {
            return Err(ShapeError::UnsupportedVersion(self.v));
        }
        match self.kind {
            Kind::Req => {
                if self.id.is_none() {
                    return Err(ShapeError::Missing(self.kind, "id"));
                }
                if self.method.is_none() {
                    return Err(ShapeError::Missing(self.kind, "method"));
                }
                if self.topic.is_some() {
                    return Err(ShapeError::Unexpected(self.kind, "topic"));
                }
            }
            Kind::Res => {
                if self.id.is_none() {
                    return Err(ShapeError::Missing(self.kind, "id"));
                }
            }
            Kind::Err => {}
            Kind::Event => {
                if self.topic.is_none() {
                    return Err(ShapeError::Missing(self.kind, "topic"));
                }
                if self.id.is_some() {
                    return Err(ShapeError::Unexpected(self.kind, "id"));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_wire_format_is_stable() {
        let env = Envelope::request(7, "system.info", &()).unwrap();
        assert_eq!(
            serde_json::to_string(&env).unwrap(),
            r#"{"v":1,"id":7,"kind":"req","method":"system.info","payload":null}"#
        );
    }

    #[test]
    fn event_has_topic_and_no_id() {
        let env = Envelope::event("live.heartbeat", &serde_json::json!({"seq": 1})).unwrap();
        assert_eq!(
            serde_json::to_string(&env).unwrap(),
            r#"{"v":1,"kind":"event","topic":"live.heartbeat","payload":{"seq":1}}"#
        );
        assert!(env.check_shape().is_ok());
    }

    #[test]
    fn missing_payload_decodes_as_null() {
        let env: Envelope =
            serde_json::from_str(r#"{"v":1,"id":1,"kind":"req","method":"system.info"}"#).unwrap();
        assert_eq!(env.payload, serde_json::Value::Null);
        assert!(env.check_shape().is_ok());
    }

    #[test]
    fn shape_errors() {
        let mut env = Envelope::request(1, "x", &()).unwrap();
        env.id = None;
        assert_eq!(env.check_shape(), Err(ShapeError::Missing(Kind::Req, "id")));

        let mut env = Envelope::request(1, "x", &()).unwrap();
        env.method = None;
        assert_eq!(
            env.check_shape(),
            Err(ShapeError::Missing(Kind::Req, "method"))
        );

        let mut env = Envelope::event("t", &()).unwrap();
        env.id = Some(3);
        assert_eq!(
            env.check_shape(),
            Err(ShapeError::Unexpected(Kind::Event, "id"))
        );

        let mut env = Envelope::response(1, &()).unwrap();
        env.v = 2;
        assert_eq!(env.check_shape(), Err(ShapeError::UnsupportedVersion(2)));
    }

    #[test]
    fn unknown_kind_is_rejected() {
        assert!(
            serde_json::from_str::<Envelope>(r#"{"v":1,"kind":"nope","payload":null}"#).is_err()
        );
    }

    #[test]
    fn payload_roundtrip() {
        let env = Envelope::response(2, &vec![1u8, 2, 3]).unwrap();
        assert_eq!(env.payload_as::<Vec<u8>>().unwrap(), vec![1, 2, 3]);
        assert!(env.payload_as::<String>().is_err());
    }
}
