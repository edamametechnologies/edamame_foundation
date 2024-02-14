use anyhow::Result;

use crate::lanscan_device_info_backend::*;
use crate::lanscan_dislike_device_info_backend::DislikeDeviceInfoBackend;
use crate::score_backend::*;

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

    async fn get_remediation_lanscan(
        &self,
        language: &str,
        device_info: &DeviceInfoBackend,
    ) -> Result<String>;

    async fn get_remediation_pwned(
        &self,
        language: &str,
        name: &str,
        user_skills: &str,
        description: &str,
        is_service: bool,
    ) -> Result<String>;

    async fn send_dislike_device_type_info(
        &self,
        dislike_device_info_backend: DislikeDeviceInfoBackend,
    ) -> Result<()>;
}
