use anyhow::{Error, Result};
use edamame_backend::advisor_todos_backend::AdvisorTodosBackend;
use edamame_backend::feedback_info_backend::FeedbackInfoBackend;
use edamame_backend::lanscan_device_info_backend::*;
use edamame_backend::lanscan_dislike_device_info_backend::DislikeDeviceInfoBackend;
use edamame_backend::policy_backend::*;
use edamame_backend::pwned_backend::BreachDetailBackend;
use edamame_backend::pwned_backend::BreachInfoBackend;
use edamame_backend::score_backend::*;
use edamame_backend::session_info_backend::SessionInfoBackend;
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
    SubscriptionLimitReached,
    InternalServerError,
    NonExistentDevice,
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
            BackendErrorCode::SubscriptionLimitReached => write!(f, "SubscriptionLimitReached"),
            BackendErrorCode::InternalServerError => write!(f, "InternalServerError"),
            BackendErrorCode::NonExistentDevice => write!(f, "NonExistentDevice"),
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
        domain_name: &str,
        policy_name: &str,
    ) -> Result<bool>;

    async fn check_policies_for_domain(
        &self,
        signature: &str,
        domain_name: &str,
    ) -> Result<Vec<PoliciesStatusBackend>>;

    async fn get_remediation_lanscan(
        &self,
        language: &str,
        device_info: &DeviceInfoBackend,
    ) -> Result<String>;

    async fn get_pwned_breaches(&self, email: &str) -> Result<Vec<BreachDetailBackend>>;

    async fn get_remediation_pwned(
        &self,
        language: &str,
        breach_info: &BreachInfoBackend,
    ) -> Result<String>;

    async fn send_user_feedback(&self, feedback_info_backend: &FeedbackInfoBackend) -> Result<()>;

    async fn send_dislike_device_type_info(
        &self,
        dislike_device_info_backend: &DislikeDeviceInfoBackend,
    ) -> Result<()>;

    async fn get_remediation_session(
        &self,
        language: &str,
        session_info: &SessionInfoBackend,
    ) -> Result<String>;

    async fn get_remediation_advisor(
        &self,
        language: &str,
        advisor_info: &AdvisorTodosBackend,
    ) -> Result<String>;

    async fn request_advisor_report(
        &self,
        language: &str,
        advisor_info: &AdvisorTodosBackend,
    ) -> Result<()>;

    /// Analyze a security todo using the internal LLM proxy
    /// The backend receives the pre-constructed prompt and forwards it to its internal LLM
    async fn get_agentic_analysis(
        &self,
        device_id: &str,
        request: &edamame_backend::agentic_backend::AgenticAnalysisRequestBackend,
        oauth_bearer_token: Option<String>,
    ) -> Result<edamame_backend::agentic_backend::AgenticAnalysisResponseBackend>;

    /// Get the user's agentic subscription status (plan name and usage)
    /// Requires OAuth bearer token for authentication.
    /// device_type and suggested_name are optional parameters for auto-populating device info.
    async fn get_agentic_subscription_status(
        &self,
        device_id: &str,
        oauth_bearer_token: String,
        device_type: Option<&str>,
        suggested_name: Option<&str>,
    ) -> Result<edamame_backend::agentic_backend::AgenticSubscriptionStatusBackend>;
}
