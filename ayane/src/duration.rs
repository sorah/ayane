//! A human-friendly duration newtype for configuration.
//!
//! Backed by [`humantime_serde`], so values deserialize from human strings such
//! as `"24h"`, `"90d"`, `"5m"`, or `"1h 30m"`. A bare number without a unit is
//! rejected.

/// A [`std::time::Duration`] that (de)serializes from strings like `"24h"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConfigDuration(#[serde(with = "humantime_serde")] pub std::time::Duration);

impl ConfigDuration {
    /// The inner [`std::time::Duration`].
    pub fn get(self) -> std::time::Duration {
        self.0
    }
}

impl From<ConfigDuration> for std::time::Duration {
    fn from(d: ConfigDuration) -> Self {
        d.0
    }
}

#[cfg(test)]
mod tests {
    fn parse(s: &str) -> std::time::Duration {
        serde_json::from_value::<super::ConfigDuration>(serde_json::Value::String(s.to_string()))
            .expect("parse duration")
            .get()
    }

    #[test]
    fn parses_units() {
        assert_eq!(parse("30s").as_secs(), 30);
        assert_eq!(parse("5m").as_secs(), 300);
        assert_eq!(parse("2h").as_secs(), 7200);
        assert_eq!(parse("1day").as_secs(), 86_400);
        assert_eq!(parse("90d").as_secs(), 7_776_000);
        assert_eq!(parse("1h 30m").as_secs(), 5400);
    }

    #[test]
    fn rejects_bad() {
        let bad = |s: &str| {
            serde_json::from_value::<super::ConfigDuration>(serde_json::Value::String(
                s.to_string(),
            ))
            .is_err()
        };
        assert!(bad("10"));
        assert!(bad("abc"));
    }
}
