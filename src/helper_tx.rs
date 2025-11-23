use crate::helper_proto::*;
use crate::order_type::*;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use edamame_proto::edamame_helper_client::EdamameHelperClient;
use edamame_proto::HelperRequest;
use lazy_static::lazy_static;
use std::str;
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::timeout;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tracing::{debug, trace};

// Implement a flag to detect if the helper is in fatal state
lazy_static! {
    pub static ref HELPER_FATAL_ERROR: Mutex<bool> = Mutex::new(false);
}

// Version
pub static CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn helper_run_utility(
    subordertype: &str,
    arg1: &str,
    arg2: &str,
    ca_pem: &str,
    client_pem: &str,
    client_key: &str,
    target: &'static str,
) -> Result<String> {
    // No signature for utility orders
    match helper_run(
        "utilityorder",
        subordertype,
        arg1,
        arg2,
        "",
        ca_pem,
        client_pem,
        client_key,
        target,
    )
    .await
    {
        Ok(result) => {
            // Set the fatal error flag
            trace!("Unsetting the HELPER_FATAL_ERROR flag");
            let mut fatal_error = HELPER_FATAL_ERROR.lock().unwrap();
            *fatal_error = false;
            Ok(result)
        }
        Err(e) => {
            if e.to_string().contains("Fatal") {
                // Set the fatal error flag
                trace!("Setting the HELPER_FATAL_ERROR flag");
                let mut fatal_error = HELPER_FATAL_ERROR.lock().unwrap();
                *fatal_error = true;
            }
            Err(e)
        }
    }
}

pub async fn helper_run_metric(
    subordertype: MetricOrderType,
    threat: &str,
    username: &str,
    signature: &str,
    ca_pem: &str,
    client_pem: &str,
    client_key: &str,
    target: &'static str,
) -> Result<String> {
    // Convert to string using the Display trait
    match helper_run(
        "metricorder",
        &subordertype.to_string(),
        threat,
        username,
        signature,
        ca_pem,
        client_pem,
        client_key,
        target,
    )
    .await
    {
        Ok(result) => {
            // Set the fatal error flag
            trace!("Unsetting the HELPER_FATAL_ERROR flag");
            let mut fatal_error = HELPER_FATAL_ERROR.lock().unwrap();
            *fatal_error = false;
            Ok(result)
        }
        Err(e) => {
            if e.to_string().contains("Fatal") {
                // Set the fatal error flag
                trace!("Setting the HELPER_FATAL_ERROR flag");
                let mut fatal_error = HELPER_FATAL_ERROR.lock().unwrap();
                *fatal_error = true;
            }
            Err(e)
        }
    }
}

async fn helper_run(
    ordertype: &str,
    subordertype: &str,
    arg1: &str,
    arg2: &str,
    signature: &str,
    ca_pem: &str,
    client_pem: &str,
    client_key: &str,
    target: &'static str,
) -> Result<String> {
    // Connect to server
    trace!("Connecting to helper server");
    let server_root_ca_cert_base64 = ca_pem.to_string();
    let server_root_ca_cert_decoded = general_purpose::STANDARD
        .decode(&server_root_ca_cert_base64)
        .expect("Failed to decode server root CA certificate");
    let server_root_ca_cert = str::from_utf8(&server_root_ca_cert_decoded)
        .expect("Failed to convert server root CA certificate to string");
    let server_root_ca_cert = Certificate::from_pem(server_root_ca_cert);

    // Decode the Base64-encoded client certificate and key
    let client_cert_base64 = client_pem.to_string();
    let client_cert_decoded = general_purpose::STANDARD
        .decode(&client_cert_base64)
        .expect("Failed to decode client certificate");
    let client_cert = str::from_utf8(&client_cert_decoded)
        .expect("Failed to convert client certificate to string");

    let client_key_base64 = client_key.to_string();
    let client_key_decoded = general_purpose::STANDARD
        .decode(&client_key_base64)
        .expect("Failed to decode client key");
    let client_key =
        str::from_utf8(&client_key_decoded).expect("Failed to convert client key to string");

    let client_identity = Identity::from_pem(client_cert, client_key);

    let tls = ClientTlsConfig::new()
        // Matching the CN of the server certificate
        .domain_name("localhost")
        .ca_certificate(server_root_ca_cert)
        .identity(client_identity);

    debug!("Connecting to helper server: {}", target);
    let channel = Channel::from_static(target).tls_config(tls)?;

    // Timeout the connection after 120 seconds, this needs to be high enough as we are querying the helper in //
    let connection = timeout(Duration::from_secs(120), channel.connect()).await??;

    let mut client = EdamameHelperClient::new(connection)
        // For session data, the messages can be large, so we need to increase the limits
        .max_decoding_message_size(1000 * 1024 * 1024)
        .max_encoding_message_size(1000 * 1024 * 1024);

    trace!("Sending request to helper server");
    let request = tonic::Request::new(HelperRequest {
        ordertype: ordertype.to_owned(),
        subordertype: subordertype.to_owned(),
        arg1: arg1.to_owned(),
        arg2: arg2.to_owned(),
        signature: signature.to_owned(),
        version: CARGO_PKG_VERSION.to_string(),
    });

    let response = match client.execute(request).await {
        Ok(response) => response,
        Err(e) => {
            return Err(anyhow!(
                "Error sending request {} / {} to helper: {:?}",
                ordertype,
                subordertype,
                e
            ))
        }
    };
    let output = response.into_inner().output;
    trace!("Helper response: {:?}", output);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_decoding_and_creation() {
        let ca_pem = std::env::var("EDAMAME_CA_PEM")
            .unwrap_or("".to_string())
            .trim_matches('"')
            .to_string();
        let client_pem = std::env::var("EDAMAME_CLIENT_PEM")
            .unwrap_or("".to_string())
            .trim_matches('"')
            .to_string();
        let client_key = std::env::var("EDAMAME_CLIENT_KEY")
            .unwrap_or("".to_string())
            .trim_matches('"')
            .to_string();

        // Decode the CA certificate
        let server_root_ca_cert_base64 = ca_pem;
        let server_root_ca_cert_decoded = general_purpose::STANDARD
            .decode(&server_root_ca_cert_base64)
            .expect("Failed to decode server root CA certificate");
        let server_root_ca_cert = str::from_utf8(&server_root_ca_cert_decoded)
            .expect("Failed to convert server root CA certificate to string");
        let server_root_ca_cert = Certificate::from_pem(server_root_ca_cert);

        // Decode the client certificate
        let client_cert_base64 = client_pem;
        let client_cert_decoded = general_purpose::STANDARD
            .decode(&client_cert_base64)
            .expect("Failed to decode client certificate");
        let client_cert = str::from_utf8(&client_cert_decoded)
            .expect("Failed to convert client certificate to string");

        // Decode the client key
        let client_key_base64 = client_key;
        let client_key_decoded = general_purpose::STANDARD
            .decode(&client_key_base64)
            .expect("Failed to decode client key");
        let client_key =
            str::from_utf8(&client_key_decoded).expect("Failed to convert client key to string");

        // Create client identity
        let client_identity = Identity::from_pem(client_cert, client_key);

        // Create TLS config
        let _ = ClientTlsConfig::new()
            .domain_name("localhost")
            .ca_certificate(server_root_ca_cert)
            .identity(client_identity);
    }
}
