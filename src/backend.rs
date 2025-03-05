use anyhow::{Error, Result};
use edamame_backend::feedback_info_backend::FeedbackInfoBackend;
use edamame_backend::lanscan_device_info_backend::*;
use edamame_backend::lanscan_dislike_device_info_backend::DislikeDeviceInfoBackend;
use edamame_backend::pwned_breach_backend::BreachDetailBackend;
use edamame_backend::score_backend::*;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(thiserror::Error, Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum BackendErrorCode {
    InputValidationFailed,
    WrongVerificationCode,
    DomainUsersLimitReached,
    DomainDevicesForUserLimitReached,
    MissingPermission,
    UnverifiedDomain,
    NonExistentDomain,
    NonExistentUser,
    DisabledUser,
    BadVersion,
    Unknown,
    InvalidSignature,
    InvalidPolicy,
    None,
}

impl fmt::Display for BackendErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BackendErrorCode::InputValidationFailed => write!(f, "InputValidationFailed"),
            BackendErrorCode::WrongVerificationCode => write!(f, "WrongVerificationCode"),
            BackendErrorCode::DomainUsersLimitReached => write!(f, "DomainUsersLimitReached"),
            BackendErrorCode::DomainDevicesForUserLimitReached => {
                write!(f, "DomainDevicesForUserLimitReached")
            }
            BackendErrorCode::MissingPermission => write!(f, "MissingPermission"),
            BackendErrorCode::UnverifiedDomain => write!(f, "UnverifiedDomain"),
            BackendErrorCode::NonExistentDomain => write!(f, "NonExistentDomain"),
            BackendErrorCode::NonExistentUser => write!(f, "NonExistentUser"),
            BackendErrorCode::DisabledUser => write!(f, "DisabledUser"),
            BackendErrorCode::BadVersion => write!(f, "BadVersion"),
            BackendErrorCode::InvalidSignature => write!(f, "InvalidSignature"),
            BackendErrorCode::InvalidPolicy => write!(f, "InvalidPolicy"),
            BackendErrorCode::Unknown => write!(f, "Unknown"),
            BackendErrorCode::None => write!(f, "None"),
        }
    }
}

impl BackendErrorCode {
    pub fn from_anyhow_error(error: Error) -> Option<Self> {
        error.downcast::<Self>().ok()
    }
}

pub trait Backend {
    // Request PIN
    async fn request_pin(
        &self,
        device_id: &str,
        connected_user: &str,
        connected_domain: &str,
        os_name: &str,
        language: &str,
    ) -> Result<()>;

    async fn report_score(
        &self,
        device_id: &str,
        language: &str,
        pin: &str,
        score: &DetailedScoreBackend,
        disconnect: bool,
    ) -> Result<String>;

    async fn request_report_from_signature(
        &self,
        email: &str,
        signature: &str,
        format: &str,
    ) -> Result<()>;

    async fn check_policy_for_domain(
        &self,
        signature: &str,
        domain: &str,
        policy_name: &str,
    ) -> Result<bool>;

    async fn get_remediation_lanscan(
        &self,
        language: &str,
        device_info: &DeviceInfoBackend,
    ) -> Result<String>;

    async fn get_pwned_breaches(&self, email: &str) -> Result<Vec<BreachDetailBackend>>;

    async fn get_remediation_pwned(
        &self,
        language: &str,
        name: &str,
        user_skills: &str,
        description: &str,
        is_service: bool,
    ) -> Result<String>;

    async fn send_user_feedback(&self, feedback_info_backend: &FeedbackInfoBackend) -> Result<()>;

    async fn send_dislike_device_type_info(
        &self,
        dislike_device_info_backend: &DislikeDeviceInfoBackend,
    ) -> Result<()>;
}
