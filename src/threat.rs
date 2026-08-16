use edamame_backend::detail_backend::CheckDetailBackend;
use edamame_backend::threat_backend::*;
use serde::{Deserialize, Serialize};
use threatmodels_rs::CloudDate;

// Only Strings in order to easily read the JSON array
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ThreatMetricEducationJSON {
    pub locale: String,
    pub class: String,
    pub target: String,
}

impl Into<ThreatMetricEducationJSONBackend> for ThreatMetricEducationJSON {
    fn into(self) -> ThreatMetricEducationJSONBackend {
        ThreatMetricEducationJSONBackend {
            locale: self.locale,
            class: self.class,
            target: self.target,
        }
    }
}

// Only Strings in order to easily read the JSON array
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ThreatMetricImplementationJSON {
    pub system: String,
    pub minversion: i32,
    pub maxversion: i32,
    pub class: String,
    pub elevation: String,
    pub target: String,
    pub education: Vec<ThreatMetricEducationJSON>,
}

impl Into<ThreatMetricImplementationJSONBackend> for ThreatMetricImplementationJSON {
    fn into(self) -> ThreatMetricImplementationJSONBackend {
        ThreatMetricImplementationJSONBackend {
            system: self.system,
            minversion: self.minversion,
            maxversion: self.maxversion,
            class: self.class,
            elevation: self.elevation,
            target: self.target,
            education: self.education.into_iter().map(|e| e.into()).collect(),
        }
    }
}

// Only Strings in order to easily read the JSON array
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ThreatMetricDescriptionJSON {
    pub locale: String,
    pub title: String,
    pub summary: String,
}

impl Into<ThreatMetricDescriptionJSONBackend> for ThreatMetricDescriptionJSON {
    fn into(self) -> ThreatMetricDescriptionJSONBackend {
        ThreatMetricDescriptionJSONBackend {
            locale: self.locale,
            title: self.title,
            summary: self.summary,
        }
    }
}

// Only Strings in order to easily read the JSON array
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ThreatMetricJSON {
    pub name: String,
    pub metrictype: String,
    pub dimension: String,
    pub severity: i32,
    pub scope: String,
    pub tags: Vec<String>,
    pub description: Vec<ThreatMetricDescriptionJSON>,
    pub implementation: ThreatMetricImplementationJSON,
    pub remediation: ThreatMetricImplementationJSON,
    pub rollback: ThreatMetricImplementationJSON,
}

impl ThreatMetricJSON {
    pub fn new() -> ThreatMetricJSON {
        ThreatMetricJSON {
            name: "".to_string(),
            metrictype: "".to_string(),
            dimension: "".to_string(),
            severity: 0,
            scope: "".to_string(),
            tags: Vec::new(),
            description: Vec::new(),
            implementation: ThreatMetricImplementationJSON::new(),
            remediation: ThreatMetricImplementationJSON::new(),
            rollback: ThreatMetricImplementationJSON::new(),
        }
    }
}

impl Into<ThreatMetricJSONBackend> for ThreatMetricJSON {
    fn into(self) -> ThreatMetricJSONBackend {
        ThreatMetricJSONBackend {
            name: self.name,
            metrictype: self.metrictype,
            dimension: self.dimension,
            severity: self.severity,
            scope: self.scope,
            tags: self.tags,
            description: self.description.into_iter().map(|d| d.into()).collect(),
            implementation: self.implementation.into(),
            remediation: self.remediation.into(),
            rollback: self.rollback.into(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ThreatMetricsJSON {
    pub name: String,
    pub extends: String,
    pub date: String,
    pub signature: String,
    pub metrics: Vec<ThreatMetricJSON>,
}

impl ThreatMetricsJSON {
    pub fn new() -> ThreatMetricsJSON {
        ThreatMetricsJSON {
            name: "".to_string(),
            extends: "".to_string(),
            date: "".to_string(),
            signature: "".to_string(),
            metrics: Vec::new(),
        }
    }
}

impl Into<ThreatMetricsJSONBackend> for ThreatMetricsJSON {
    fn into(self) -> ThreatMetricsJSONBackend {
        ThreatMetricsJSONBackend {
            name: self.name,
            extends: self.extends,
            date: self.date,
            signature: self.signature,
            metrics: self.metrics.into_iter().map(|m| m.into()).collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, PartialOrd)]
pub enum ThreatStatus {
    Active,
    Inactive,
    Unknown,
}

/// Why a capture failed and left its check in [`ThreatStatus::Unknown`].
///
/// A bare `Unknown` is indistinguishable between "the helper is down",
/// "host policy blocks the shell we need", and "this binary predates the
/// check", yet those need very different actions from the user. On Windows
/// the distinction matters most: a policy that blocks PowerShell spawn takes
/// out every `cli`-class check at once.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Eq, PartialEq, PartialOrd)]
pub enum ThreatUnknownReason {
    /// The EDAMAME Helper is not reachable.
    HelperUnavailable,
    /// The helper is reachable but speaks a different protocol version.
    HelperVersionMismatch,
    /// The host refused to start the process the check needs (AppLocker,
    /// WDAC, execution policy, inaccessible PATH or working directory).
    PolicyBlocked,
    /// The check needs an elevation this process does not hold.
    ElevationUnavailable,
    /// The cloud threat model asks for a check this binary does not implement.
    CheckUnsupported,
    /// Anything else -- the case that still deserves a Sentry error.
    Other,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ThreatMetric {
    pub metric: ThreatMetricJSON,
    // Can be empty
    pub timestamp: String,
    pub status: ThreatStatus,
    // Track the output of the order (not exported to the backend)
    pub output: String,
    /// Set when `status` is [`ThreatStatus::Unknown`] and the capture failed,
    /// cleared on every successful capture. Not carried on
    /// [`ThreatMetricBackend`]: like `output`, this stays on the device.
    #[serde(default)]
    pub unknown_reason: Option<ThreatUnknownReason>,
    /// Raw capture error behind `unknown_reason`, for support and the CLI.
    /// Never shown as-is in the app -- the app renders the localized reason.
    #[serde(default)]
    pub unknown_detail: String,
    /// Governance evidence for this check, cached at capture time so the report
    /// carries what was observed then rather than whatever the runners hold when
    /// the report is finally sent. `None` for non-AI checks and for AI checks
    /// that are not Active.
    ///
    /// Not a CloudModel field, and not carried on [`ThreatMetricBackend`]: the
    /// Hub receives this collated per domain in `DetailedScoreBackend.details`,
    /// where consent gates it in one place.
    #[serde(default)]
    pub ai_detail: Option<CheckDetailBackend>,
}

impl ThreatMetric {
    pub fn new() -> ThreatMetric {
        ThreatMetric {
            metric: ThreatMetricJSON::new(),
            timestamp: "".to_string(),
            status: ThreatStatus::Unknown,
            output: "".to_string(),
            unknown_reason: None,
            unknown_detail: "".to_string(),
            ai_detail: None,
        }
    }
}

impl Into<ThreatStatusBackend> for ThreatStatus {
    fn into(self) -> ThreatStatusBackend {
        match self {
            ThreatStatus::Active => ThreatStatusBackend::Active,
            ThreatStatus::Inactive => ThreatStatusBackend::Inactive,
            ThreatStatus::Unknown => ThreatStatusBackend::Unknown,
        }
    }
}

impl Into<ThreatMetricBackend> for ThreatMetric {
    fn into(self) -> ThreatMetricBackend {
        ThreatMetricBackend {
            metric: self.metric.into(),
            timestamp: self.timestamp,
            status: self.status.into(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ThreatMetrics {
    pub metrics: Vec<ThreatMetric>,
    pub name: String,
    pub extends: String,
    pub date: String,
    pub signature: String,
}

impl ThreatMetrics {
    pub fn new() -> ThreatMetrics {
        ThreatMetrics {
            metrics: Vec::new(),
            name: "".to_string(),
            extends: "".to_string(),
            date: "".to_string(),
            signature: "".to_string(),
        }
    }
}

impl Into<ThreatMetricsBackend> for ThreatMetrics {
    fn into(self) -> ThreatMetricsBackend {
        ThreatMetricsBackend {
            metrics: self.metrics.into_iter().map(|m| m.into()).collect(),
            name: self.name,
            extends: self.extends,
            date: self.date,
            signature: self.signature,
        }
    }
}

impl CloudDate for ThreatMetrics {
    fn get_date(&self) -> Option<&str> {
        if self.date.is_empty() {
            None
        } else {
            Some(&self.date)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `ThreatMetric` written by an older build carries none of the optional
    /// fields. Losing the `#[serde(default)]` on any of them makes the whole
    /// `OrderHistory` parse fail on upgrade, and `OrderHistoryTrait::read()`
    /// answers a parse failure by resetting to an empty history -- so the user
    /// silently loses every recorded remediation.
    #[test]
    fn deserializes_a_metric_written_before_the_optional_fields_existed() {
        let mut json = serde_json::to_value(ThreatMetric::new()).expect("serialize");
        let object = json
            .as_object_mut()
            .expect("metric serializes to an object");
        for field in ["unknown_reason", "unknown_detail", "ai_detail"] {
            assert!(
                object.remove(field).is_some(),
                "{field} is missing from the serialized shape, so this test no longer covers it"
            );
        }

        let metric: ThreatMetric =
            serde_json::from_value(json).expect("old-shape metric must still deserialize");

        assert_eq!(metric.unknown_reason, None);
        assert_eq!(metric.unknown_detail, "");
        assert_eq!(metric.ai_detail, None);
    }
}
