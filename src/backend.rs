use anyhow::Result;

use crate::score_backend::*;
use crate::lanscan_device_info_backend::*;

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

    // Report anonymous score
    async fn report_score(
        &self,
        device_id: &str,
        language: &str,
        pin: &str,
        disconnect: bool,
        score: &NumericalScoreBackend,
    ) -> Result<()>;

    async fn report_detailed_score(
        &self,
        device_id: &str,
        language: &str,
        pin: &str,
        score: &DetailedScoreBackend,
    ) -> Result<()>;

    async fn fetch_lanscan_remediation(
        &self,
        language: &str,
        device_info: &DeviceInfoBackend,
    ) -> Result<String>;

    async fn fetch_breach_remediation(
        &self,
        language: &str,
        name: &str,
        user_skills: &str,
        breach_description: &str,
        is_service: bool
    ) -> Result<String>;
}