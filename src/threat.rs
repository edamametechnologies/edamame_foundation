use serde::{Deserialize, Serialize};

// Only Strings in order to easily read the JSON array
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ThreatMetricEducationJSON {
    pub locale: String,
    pub class: String,
    pub target: String,
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
    pub education: Vec<ThreatMetricEducationJSON>
}

// Only Strings in order to easily read the JSON array
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ThreatMetricDescriptionJSON {
    pub locale: String,
    pub title: String,
    pub summary: String
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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ThreatMetricsJSON {
    pub name: String,
    pub extends: String,
    pub date: String,
    pub signature: String,
    pub metrics: Vec<ThreatMetricJSON>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub enum ThreatStatus {
    Active,
    Inactive,
    Unknown
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ThreatMetric {
    pub metric: ThreatMetricJSON,
    // Can be empty
    pub timestamp: String,
    pub status: ThreatStatus,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ThreatMetrics {
    pub metrics: Vec<ThreatMetric>,
    // Copied field from the JSON threat model
    pub name: String,
    pub extends: String,
    pub date: String,
    pub signature: String,
    pub timestamp: String,
}