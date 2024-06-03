use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::HashMap;
use strum_macros::EnumString;

// Health, we keep the case of the enum values to match the Dart enum values
#[derive(EnumString, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum HealthMetricType {
    ACTIVE_ENERGY_BURNED,
    AUDIOGRAM,
    BASAL_ENERGY_BURNED,
    BLOOD_GLUCOSE,
    BLOOD_OXYGEN,
    BLOOD_PRESSURE_DIASTOLIC,
    BLOOD_PRESSURE_SYSTOLIC,
    BODY_FAT_PERCENTAGE,
    BODY_MASS_INDEX,
    BODY_TEMPERATURE,
    DIETARY_CARBS_CONSUMED,
    DIETARY_ENERGY_CONSUMED,
    DIETARY_FATS_CONSUMED,
    DIETARY_PROTEIN_CONSUMED,
    ELECTRODERMAL_ACTIVITY,
    FORCED_EXPIRATORY_VOLUME,
    HEART_RATE,
    HEART_RATE_VARIABILITY_SDNN,
    HEIGHT,
    RESPIRATORY_RATE,
    PERIPHERAL_PERFUSION_INDEX,
    STEPS,
    WAIST_CIRCUMFERENCE,
    WEIGHT,
    FLIGHTS_CLIMBED,
    DISTANCE_WALKING_RUNNING,
    MINDFULNESS,
    SLEEP_AWAKE,
    SLEEP_ASLEEP,
    SLEEP_IN_BED,
    SLEEP_DEEP,
    SLEEP_REM,
    WATER,
    EXERCISE_TIME,
    WORKOUT,
    HEADACHE_NOT_PRESENT,
    HEADACHE_MILD,
    HEADACHE_MODERATE,
    HEADACHE_SEVERE,
    HEADACHE_UNSPECIFIED,
    ELECTROCARDIOGRAM,
    HIGH_HEART_RATE_EVENT,
    IRREGULAR_HEART_RATE_EVENT,
    LOW_HEART_RATE_EVENT,
    RESTING_HEART_RATE,
    WALKING_HEART_RATE,
    NUTRITION,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HealthNumericValue {
    // As found in the Dart code, this is a string
    #[serde(rename = "numericValue")]
    pub numeric_value: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HealthDataPoint {
    pub data_type: HealthMetricType,
    pub value: HealthNumericValue,
    pub unit: String,
    pub date_from: String,
    pub date_to: String,
    pub platform_type: String,
    pub device_id: String,
    pub source_id: String,
    pub source_name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HealthTimeSeries {
    pub data: Vec<(DateTime<Utc>, HealthDataPoint)>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Health {
    #[serde_as(as = "Vec<(_, _)>")]
    pub metrics: HashMap<HealthMetricType, HealthTimeSeries>,
    pub physical_activity: i32,
    pub rest_and_recovery: i32,
    pub physio_stress_indicators: i32,
    pub health_habits: i32,
    pub overall: i32,
    pub stars: f64,
}

impl Health {
    pub fn new() -> Health {
        Health {
            metrics: HashMap::new(),
            physical_activity: 0,
            rest_and_recovery: 0,
            physio_stress_indicators: 0,
            health_habits: 0,
            overall: 0,
            stars: 0.0,
        }
    }
}
