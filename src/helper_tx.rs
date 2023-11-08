use log::{error, trace};
use std::error::Error;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use std::time::Duration;
use tokio::time::timeout;
use base64::{Engine as _, engine::general_purpose};
use std::str;

// Standard Mutex
use std::sync::Mutex;
use lazy_static::lazy_static;

use crate::foundation::*;
use crate::order_type::*;
use crate::helper_proto::*;

// Proto generated server traits
use edamame_proto::edamame_helper_client::EdamameHelperClient;
use edamame_proto::{HelperRequest};

// Implement a flag to detect if the helper is in fatal state
lazy_static! {
    pub static ref FATAL_ERROR: Mutex<bool> = Mutex::new(false);
}

pub async fn helper_run_utility(subordertype: &str, arg1: &str, arg2: &str) -> Result<String, Box<dyn Error>> {
    // No signature for utility orders
    helper_run("utilityorder", subordertype , arg1, arg2, "").await
}

pub async fn helper_run_metric(subordertype: MetricOrderType, threat: &str, username: &str, signature: &str) -> Result<String, Box<dyn Error>> {
    // Convert to string using the Display trait
    match helper_run("metricorder", &subordertype.to_string(), threat, username, signature).await {
        Ok(result) => {
            // Set the fatal error flag
            trace!("Unsetting the FATAL_ERROR flag");
            let mut fatal_error = FATAL_ERROR.lock().unwrap();
            *fatal_error = false;
            Ok(result)
        },
        Err(e) => {
            if e.to_string().contains("Fatal") {
                // Set the fatal error flag
                trace!("Setting the FATAL_ERROR flag");
                let mut fatal_error = FATAL_ERROR.lock().unwrap();
                *fatal_error = true;
            }
            error!("{}", e);
            Err(e)
        }
    }
}

async fn helper_run(ordertype: &str, subordertype: &str, arg1: &str, arg2: &str, signature: &str) -> Result<String, Box<dyn Error>> {

    // Connect to server
    trace!("Connecting to helper server");
    let server_root_ca_cert_base64 = EDAMAME_CA_PEM.to_string();
    let server_root_ca_cert_decoded = general_purpose::STANDARD.decode(&server_root_ca_cert_base64).expect("Failed to decode server root CA certificate");
    let server_root_ca_cert = str::from_utf8(&server_root_ca_cert_decoded).expect("Failed to convert server root CA certificate to string");
    let server_root_ca_cert = Certificate::from_pem(server_root_ca_cert);

    // Decode the Base64-encoded client certificate and key
    let client_cert_base64 = EDAMAME_CLIENT_PEM.to_string();
    let client_cert_decoded = general_purpose::STANDARD.decode(&client_cert_base64).expect("Failed to decode client certificate");
    let client_cert = str::from_utf8(&client_cert_decoded).expect("Failed to convert client certificate to string");

    let client_key_base64 = EDAMAME_CLIENT_KEY.to_string();
    let client_key_decoded = general_purpose::STANDARD.decode(&client_key_base64).expect("Failed to decode client key");
    let client_key = str::from_utf8(&client_key_decoded).expect("Failed to convert client key to string");

    let client_identity = Identity::from_pem(client_cert, client_key);

    let tls = ClientTlsConfig::new()
        // Matching the CN of the server certificate
        .domain_name("localhost")
        .ca_certificate(server_root_ca_cert)
        .identity(client_identity);

    let channel = Channel::from_static(TARGET)
        .tls_config(tls)?;

    // Timeout the connection after 1 second
    let connection = timeout(
        Duration::from_secs(1),
        channel.connect(),
    ).await??;

    let mut client = EdamameHelperClient::new(connection);

    trace!("Sending request to helper server");
    let request = tonic::Request::new(HelperRequest {
        ordertype: ordertype.to_owned(),
        subordertype: subordertype.to_owned(),
        arg1: arg1.to_owned(),
        arg2: arg2.to_owned(),
        signature: signature.to_owned(),
        version: FOUNDATION_VERSION.to_string(),
    });

    let response = client.execute(request).await?;
    let output = response.into_inner().output;
    trace!("Helper response: {:?}", output);
    Ok(output)
}
