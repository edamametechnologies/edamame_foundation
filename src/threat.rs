use edamame_backend::threat_backend::*;
use edamame_models::CloudDate;
use serde::{Deserialize, Serialize};

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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ThreatMetric {
    pub metric: ThreatMetricJSON,
    // Can be empty
    pub timestamp: String,
    pub status: ThreatStatus,
    // Track the output of the order (not exported to the backend)
    pub output: String,
}

impl ThreatMetric {
    pub fn new() -> ThreatMetric {
        ThreatMetric {
            metric: ThreatMetricJSON::new(),
            timestamp: "".to_string(),
            status: ThreatStatus::Unknown,
            output: "".to_string(),
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
