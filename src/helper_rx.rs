use crate::helper_proto::*;
use crate::helper_rx_utility::*;
#[cfg(all(
    any(target_os = "macos", target_os = "linux"),
    feature = "packetcapture"
))]
use crate::lanscan_capture::LANScanCapture;
use crate::lanscan_interface::*;
use crate::lanscan_mdns::mdns_flush;
#[cfg(all(
    any(target_os = "macos", target_os = "linux"),
    feature = "packetcapture"
))]
use crate::lanscan_sessions::SessionFilter;
use crate::runner_cli::*;
use crate::threat_factory::*;
use anyhow::{anyhow, Error, Result};
use base64::engine::general_purpose;
use base64::Engine;
use chrono::Utc;
use edamame_proto::edamame_helper_server::{EdamameHelper, EdamameHelperServer};
use edamame_proto::{HelperRequest, HelperResponse};
use lazy_static::lazy_static;
#[cfg(target_os = "macos")]
use libc::EACCES;
#[cfg(target_os = "macos")]
use std::fs::File;
#[cfg(target_os = "macos")]
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::str;
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::sync::Mutex;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Code, Request, Response, Status};
use tracing::{debug, error, info, trace, warn};

#[cfg(all(
    any(target_os = "macos", target_os = "linux"),
    feature = "packetcapture"
))]
lazy_static! {
    pub static ref CAPTURE: Arc<Mutex<LANScanCapture>> =
        Arc::new(Mutex::new(LANScanCapture::new()));
}

lazy_static! {
    // Branch name
    pub static ref BRANCH: Arc<Mutex<String>> = Arc::new(Mutex::new("".to_string()));
    // Current default interface
    pub static ref INTERFACES_NAMES: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    pub static ref INTERFACES_IPS: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    pub static ref INTERFACES_PREFIX: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    // Last interface check timestamp
    pub static ref INTERFACE_CHECK_TIME: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
}

// Version
pub static CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Default)]
pub struct Helper {}

#[tonic::async_trait]
impl EdamameHelper for Helper {
    async fn execute(
        &self,
        request: Request<HelperRequest>,
    ) -> Result<Response<HelperResponse>, Status> {
        let certs = request
            .peer_certs()
            .expect("Client did not send its certs!");

        trace!("Got {} peer certs!", certs.len());

        let req_order = request.into_inner();
        let ordertype = req_order.ordertype;
        let subordertype = req_order.subordertype;
        let arg1 = req_order.arg1;
        let arg2 = req_order.arg2;
        let signature = req_order.signature;
        let version = req_order.version;

        debug!("Executing order {} / {}", ordertype, subordertype);
        rpc_run_safe(
            &ordertype,
            &subordertype,
            &arg1,
            &arg2,
            &signature,
            &version,
        )
        .await
    }
}

pub async fn rpc_run_safe(
    ordertype: &str,
    subordertype: &str,
    arg1: &str,
    arg2: &str,
    signature: &str,
    version: &str,
) -> Result<Response<HelperResponse>, Status> {
    rpc_run(ordertype, subordertype, arg1, arg2, signature, version)
        .await
        .map(|output| {
            let response = HelperResponse { output };
            Response::new(response)
        })
        .map_err(|e| {
            // No error but a warning to prevent flooding Sentry in case we upgrade the helper
            warn!("Error while executing order: {}", e);
            Status::new(Code::Internal, e.to_string())
        })
}

pub struct ServerControl {
    pub stop: Option<oneshot::Sender<()>>,
}

impl ServerControl {
    pub fn new() -> Self {
        ServerControl { stop: None }
    }

    pub async fn start_server(
        &mut self,
        server_pem: &str,
        server_key: &str,
        client_ca_cert: &str,
        server: &str,
        branch: &str,
    ) -> Result<()> {
        // Store branch name
        {
            let mut branch_lock = BRANCH.lock().await;
            *branch_lock = branch.to_string();
        }

        let (tx, rx) = oneshot::channel::<()>();
        self.stop = Some(tx);

        let cert_base64 = server_pem.to_string();
        let key_base64 = server_key.to_string();

        // Decode Base64 to original PEM format
        let cert_decoded = general_purpose::STANDARD
            .decode(&cert_base64)
            .expect("Failed to decode Base64");
        let cert = str::from_utf8(&cert_decoded).expect("Failed to convert to string");

        let key_decoded = general_purpose::STANDARD
            .decode(&key_base64)
            .expect("Failed to decode Base64");
        let key = str::from_utf8(&key_decoded).expect("Failed to convert to string");

        let server_identity = Identity::from_pem(cert, key);

        let client_ca_cert_base64 = client_ca_cert.to_string();

        // Decode Base64 to original PEM format
        let client_ca_cert_decoded = general_purpose::STANDARD
            .decode(&client_ca_cert_base64)
            .expect("Failed to decode Base64");
        let client_ca_cert =
            str::from_utf8(&client_ca_cert_decoded).expect("Failed to convert to string");
        let client_ca_cert = Certificate::from_pem(client_ca_cert);

        let edamame_server = Helper::default();

        let tls = ServerTlsConfig::new()
            .identity(server_identity)
            .client_ca_root(client_ca_cert);

        let addr: &str = server;
        let sock: SocketAddr = addr.parse().expect("Unable to parse socket address");

        info!(
            "EDAMAME Helper listening on {:?} - foundation version is {:?}",
            sock, CARGO_PKG_VERSION
        );

        // Check TLS configuration
        let server_future = match Server::builder().tls_config(tls) {
            Ok(mut builder) => builder
                .add_service(EdamameHelperServer::new(edamame_server))
                .serve(sock),
            Err(e) => {
                error!("TLS configuration error: {}", e);
                return Err(anyhow!(e));
            }
        };

        tokio::select! {
            result = server_future => {
                match result {
                    Ok(_) => {
                        info!("EDAMAME Helper stopped");
                        Ok(())
                    }
                    Err(e) => {
                        error!("EDAMAME Helper server error: {}", e);
                        Err(anyhow!(e))
                    }
                }
            }
            _ = rx => {
                info!("EDAMAME Helper gracefully shutting down");
                Ok(())
            }
        }
    }

    pub async fn stop_server(&mut self) -> Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        Ok(())
    }
}

// Detect and check interface changes
pub async fn check_interfaces_changes() -> bool {
    // Detect the interface name and ip if not done for 10 seconds, detect changes
    if chrono::Utc::now().timestamp() - *INTERFACE_CHECK_TIME.lock().await as i64 > 10 {
        let interfaces = get_valid_network_interfaces();
        let mut interfaces_changed = false;

        // Make a vector of the interfaces ips
        let interfaces_ips = interfaces
            .iter()
            .map(|i| i.0.clone())
            .collect::<Vec<String>>();
        // Make a vector of the interfaces prefixes
        let interfaces_prefixes = interfaces.iter().map(|i| i.1).collect::<Vec<u8>>();
        // Make a vector of the interfaces names
        let interfaces_names = interfaces
            .iter()
            .map(|i| i.2.clone())
            .collect::<Vec<String>>();

        // Check if the interface name has changed
        let interfaces_names_old = INTERFACES_NAMES.lock().await.clone();
        if interfaces_names_old != interfaces_names {
            info!(
                "A name changed has been detected from {:?} to {:?}",
                interfaces_names_old, interfaces_names
            );
            interfaces_changed = true;
            *INTERFACES_NAMES.lock().await = interfaces_names;
        }

        // Check if the interface ip has changed
        let interfaces_ips_old = INTERFACES_IPS.lock().await.clone();
        if interfaces_ips_old != interfaces_ips {
            info!(
                "An IP changed has been detected from {:?} to {:?}",
                interfaces_ips_old, interfaces_ips
            );
            interfaces_changed = true;
            *INTERFACES_IPS.lock().await = interfaces_ips;
        }

        // Check if the interface subnet has changed
        let interfaces_prefixes_old = INTERFACES_PREFIX.lock().await.clone();
        if interfaces_prefixes_old != interfaces_prefixes {
            info!(
                "A subnet changed has been detected from {:?} to {:?}",
                interfaces_prefixes_old, interfaces_prefixes
            );
            interfaces_changed = true;
            *INTERFACES_PREFIX.lock().await = interfaces_prefixes;
        }

        // Update the interface check time
        *INTERFACE_CHECK_TIME.lock().await = Utc::now().timestamp() as u64;

        return interfaces_changed;
    }
    false
}

// Receiving end of the order - the RPC server error handling requires Send + Sync...
pub async fn rpc_run(
    ordertype: &str,
    subordertype: &str,
    arg1: &str,
    arg2: &str,
    signature: &str,
    version: &str,
) -> Result<String> {
    // Force update if any of the key mandatory fields are empty - this would indicate a protocol error
    if version.is_empty() || ordertype.is_empty() {
        return order_error("order received with empty version of ordertype", true);
    }

    // Check the version (major.minor)
    let major_version = version.split('.').take(2).collect::<Vec<&str>>().join(".");
    let major_cargo_version = CARGO_PKG_VERSION
        .split('.')
        .take(2)
        .collect::<Vec<&str>>()
        .join(".");
    if major_version > major_cargo_version {
        return order_error(
            &format!(
                "order received with foundation major version mismatch - received {} > {}",
                major_version, major_cargo_version
            ),
            true,
        );
    }

    // Display the order and the arguments, ignore empty arguments
    if arg1.is_empty() && arg2.is_empty() {
        info!("Executing order {} / {}", ordertype, subordertype);
    } else if arg2.is_empty() {
        info!(
            "Executing order {} / {} with arg#1 {}",
            ordertype, subordertype, arg1
        );
    } else {
        info!(
            "Executing order {} / {} with arg#1 {} and arg#2 {}",
            ordertype, subordertype, arg1, arg2
        );
    }

    match ordertype {
        "metricorder" => {
            let threat = arg1;
            let username = arg2;

            // Lock the threats object
            let metrics = THREATS.read().await;
            // Get a copy of the current signature
            let current_signature = metrics.get_signature().await;
            // Force update if signature mismatch
            if signature != current_signature {
                info!(
                    "Signature mismatch current is: {}, received is: {}",
                    current_signature, signature
                );
                // Perform update
                let branch = BRANCH.lock().await.clone();
                match update(&branch, false).await {
                    Ok(_) => {
                        info!(
                            "Updated model from backend successfully - new signature is: {}",
                            metrics.get_signature().await
                        );
                    }
                    Err(e) => {
                        // Only warn this can happen if the device is offline
                        warn!("Failed to update threat model from backend: {}", e);
                        return order_error(&format!("metricorder received with signature mismatch but failed to update model from backend: {}", e), true);
                    }
                }
            }

            let mut implementation = None;
            // Extract back the threat by name
            let metrics = get_threat_metrics().await;
            for m in metrics.metrics {
                if m.metric.name == threat {
                    match subordertype {
                        "capture" => implementation = Some(m.metric.implementation.clone()),
                        "remediate" => implementation = Some(m.metric.remediation.clone()),
                        "rollback" => implementation = Some(m.metric.rollback.clone()),
                        _ => {
                            return order_error(
                                &format!(
                                    "unknown subordertype {} for metricorder {}",
                                    subordertype, threat
                                ),
                                false,
                            );
                        }
                    }
                    break;
                }
            }

            return if implementation.is_some() {
                let implementation_clone = implementation.unwrap();
                trace!("Found implementation for threat: {}", threat);
                if !implementation_clone.target.is_empty() && !implementation_clone.class.is_empty()
                {
                    let class = implementation_clone.class.as_str();
                    let target = implementation_clone.target.as_str();
                    // The personate parameter forces the execution into the context of username
                    // We could use an empty username to indicate there is no need to personate, but we keep it as is for now in case we find other use cases for the username
                    // Only apply to admin class
                    let personate = &implementation_clone.class == "admin";
                    trace!("Running target {} and class {}", target, class);
                    if !class.is_empty() {
                        return if personate && username.is_empty() {
                            order_error(&format!("personate required but no username provided for metricorder {}", threat), false)
                        } else {
                            match class {
                                "cli" => run_cli(target, username, personate).await,
                                "internal" => {
                                    // We don't have any internal implementation within the helper for now
                                    order_error(&format!("internal implementation type not implemented for metricorder {}", threat), false)
                                }
                                _ => order_error(
                                    &format!(
                                        "unknown or unimplemented implementation type {} for {}",
                                        class, threat
                                    ),
                                    false,
                                ),
                            }
                        };
                    } else {
                        order_error(
                            &format!("no implementation type found for metricorder {}", threat),
                            false,
                        )
                    }
                } else {
                    order_error(
                        &format!(
                            "missing target or class in implementation or metricorder {}",
                            threat
                        ),
                        false,
                    )
                }
            } else {
                order_error(
                    &format!("no implementation found for metricorder {}", threat),
                    false,
                )
            };
        }
        "utilityorder" => match subordertype {
            "getappleid_email" => {
                let username = arg2;
                run_cli("defaults read MobileMeAccounts Accounts | grep AccountID | grep -o \"\\\".*\\\"\" | sed \"s/\\\"//g\" | tr -d \"\\n\"", username, true).await
            }
            "mdns_resolve" => {
                if check_interfaces_changes().await {
                    mdns_flush().await;
                }
                let json_addresses = arg1;
                match mdns_resolve(json_addresses).await {
                    Ok(output) => Ok(output),
                    Err(e) => {
                        error!("Error performing mdns_resolve: {}", e);
                        order_error(&format!("error performing mdns_resolve: {}", e), false)
                    }
                }
            }
            "arp_resolve" => {
                let json_addresses = arg1;
                match arp_resolve(json_addresses).await {
                    Ok(output) => Ok(output),
                    Err(e) => {
                        // Only warn
                        warn!("Error performing arp_resolve: {}", e);
                        order_error(&format!("error performing arp_resolve: {}", e), false)
                    }
                }
            }
            "helper_check" => {
                // Return the current helper version
                let result = CARGO_PKG_VERSION.to_string();
                Ok(result)
            }
            "helper_flags" => {
                // Return additional information in the form flag=value,...
                #[cfg(target_os = "macos")]
                {
                    let path = "/Library/Application Support/com.apple.TCC/TCC.db";

                    let file_result = File::open(path);

                    let full_disk_access = match file_result {
                        Ok(_) => true,
                        Err(ref e) if e.kind() == ErrorKind::PermissionDenied => false,
                        Err(ref e) if e.raw_os_error() == Some(EACCES) => false,
                        Err(e) => {
                            // Handle other errors
                            error!("Failed to check full disk access: {}", e);
                            false
                        }
                    };
                    let result = format!("full_disk_access={}", full_disk_access);
                    Ok(result)
                }

                #[cfg(not(target_os = "macos"))]
                {
                    Ok("".to_string())
                }
            }
            #[cfg(all(
                any(target_os = "macos", target_os = "linux"),
                feature = "packetcapture"
            ))]
            "start_capture" => {
                // Check if already capturing
                if CAPTURE.lock().await.is_capturing().await {
                    return order_error("capture already started", false);
                }
                // Get latest interfaces
                let _ = check_interfaces_changes().await;
                let interfaces = INTERFACES_NAMES.lock().await.clone();
                // Convert the vec into a comma separated string
                let interfaces_string = interfaces.join(",");
                CAPTURE.lock().await.start(&interfaces_string).await;
                Ok("".to_string())
            }
            #[cfg(all(
                any(target_os = "macos", target_os = "linux"),
                feature = "packetcapture"
            ))]
            "stop_capture" => {
                CAPTURE.lock().await.stop().await;
                Ok("".to_string())
            }
            #[cfg(all(
                any(target_os = "macos", target_os = "linux"),
                feature = "packetcapture"
            ))]
            "is_capturing" => {
                let is_capturing = CAPTURE.lock().await.is_capturing().await;
                let result = is_capturing.to_string();
                info!("Returning is_capturing: {}", result);
                Ok(result)
            }
            #[cfg(all(
                any(target_os = "macos", target_os = "linux"),
                feature = "packetcapture"
            ))]
            "set_whitelist" => {
                let whitelist_name = arg1;
                CAPTURE.lock().await.set_whitelist(whitelist_name).await;
                Ok("".to_string())
            }
            #[cfg(all(
                any(target_os = "macos", target_os = "linux"),
                feature = "packetcapture"
            ))]
            "get_whitelist" => {
                let whitelist = CAPTURE.lock().await.get_whitelist().await;
                info!("Returning whitelist: {}", whitelist);
                Ok(whitelist)
            }
            #[cfg(all(
                any(target_os = "macos", target_os = "linux"),
                feature = "packetcapture"
            ))]
            "set_filter" => {
                match serde_json::from_str::<SessionFilter>(arg1) {
                    Ok(filter) => CAPTURE.lock().await.set_filter(filter).await,
                    Err(e) => {
                        error!("Invalid argument for set_filter {} : {}", arg1, e);
                        return order_error(
                            &format!("invalid argument for set_filter: {}", arg1),
                            false,
                        );
                    }
                };
                Ok("".to_string())
            }
            #[cfg(all(
                any(target_os = "macos", target_os = "linux"),
                feature = "packetcapture"
            ))]
            "get_filter" => {
                let filter = CAPTURE.lock().await.get_filter().await;
                let json_filter = match serde_json::to_string(&filter) {
                    Ok(json) => json,
                    Err(e) => {
                        error!("Error serializing filter to JSON: {}", e);
                        return order_error(
                            &format!("error serializing filter to JSON: {}", e),
                            false,
                        );
                    }
                };
                info!("Returning filter: {}", json_filter);
                Ok(json_filter)
            }
            #[cfg(all(
                any(target_os = "macos", target_os = "linux"),
                feature = "packetcapture"
            ))]
            "get_sessions" => {
                if check_interfaces_changes().await && CAPTURE.lock().await.is_capturing().await {
                    CAPTURE.lock().await.stop().await;
                    // Get the new interfaces
                    let interfaces = INTERFACES_NAMES.lock().await.clone();
                    // Convert the vec into a comma separated string
                    let interfaces_string = interfaces.join(",");
                    info!(
                        "Interfaces have changed, restarting capture on {:?}",
                        interfaces_string
                    );
                    CAPTURE.lock().await.start(&interfaces_string).await;
                }
                let sessions = CAPTURE.lock().await.get_sessions().await;
                let json_sessions = match serde_json::to_string(&sessions) {
                    Ok(json) => json,
                    Err(e) => {
                        error!("Error serializing sessions to JSON: {}", e);
                        return order_error(
                            &format!("error serializing sessions to JSON: {}", e),
                            false,
                        );
                    }
                };
                info!("Returning {} sessions", sessions.len());
                Ok(json_sessions)
            }
            #[cfg(all(
                any(target_os = "macos", target_os = "linux"),
                feature = "packetcapture"
            ))]
            "get_current_sessions" => {
                if check_interfaces_changes().await && CAPTURE.lock().await.is_capturing().await {
                    CAPTURE.lock().await.stop().await;
                    // Get the new interfaces
                    let interfaces = INTERFACES_NAMES.lock().await.clone();
                    // Convert the vec into a comma separated string
                    let interfaces_string = interfaces.join(",");
                    info!(
                        "Interfaces have changed, restarting capture on {:?}",
                        interfaces_string
                    );
                    CAPTURE.lock().await.start(&interfaces_string).await;
                }
                let active_sessions = CAPTURE.lock().await.get_current_sessions().await;
                let json_active_sessions = match serde_json::to_string(&active_sessions) {
                    Ok(json) => json,
                    Err(e) => {
                        error!("Error serializing current sessions to JSON: {}", e);
                        return order_error(
                            &format!("error serializing current sessions to JSON: {}", e),
                            false,
                        );
                    }
                };
                info!("Returning {} current sessions", active_sessions.len());
                Ok(json_active_sessions)
            }
            #[cfg(all(
                any(target_os = "macos", target_os = "linux"),
                feature = "packetcapture"
            ))]
            "get_whitelist_conformance" => {
                let conformance = CAPTURE
                    .lock()
                    .await
                    .get_whitelist_conformance()
                    .await
                    .to_string();
                let result = conformance.to_string();
                info!("Returning whitelist conformance: {}", result);
                Ok(result)
            }
            #[cfg(all(
                any(target_os = "macos", target_os = "linux"),
                feature = "packetcapture"
            ))]
            "get_whitelist_exceptions" => {
                let exceptions = CAPTURE.lock().await.get_whitelist_exceptions().await;
                let json_exceptions = match serde_json::to_string(&exceptions) {
                    Ok(json) => json,
                    Err(e) => {
                        error!("Error serializing whitelist exceptions to JSON: {}", e);
                        return order_error(
                            &format!("error serializing whitelist exceptions to JSON: {}", e),
                            false,
                        );
                    }
                };
                info!("Returning {} whitelist exceptions", exceptions.len());
                Ok(json_exceptions)
            }
            _ => order_error(
                &format!("unknown or unimplemented utilityorder {}", subordertype),
                false,
            ),
        },
        _ => order_error(
            &format!("unknown or unimplemented order {}", ordertype),
            false,
        ),
    }
}

fn order_error(comment: &str, fatal: bool) -> Result<String> {
    let msg = if fatal {
        format!("Fatal order error : {}", comment)
    } else {
        format!("Order error : {}", comment)
    };
    error!("{}", msg);
    Err(Error::msg(msg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use edamame_proto::edamame_helper_client::EdamameHelperClient;
    use edamame_proto::edamame_helper_server::{EdamameHelper, EdamameHelperServer};
    use std::str;
    use tokio::time::{sleep, timeout, Duration};
    use tonic::transport::Channel;
    use tonic::transport::{Certificate, ClientTlsConfig, Identity};

    #[test]
    fn test_certificate_decoding_and_creation() {
        let server_pem = std::env::var("EDAMAME_SERVER_PEM").unwrap_or("".to_string());
        let server_key = std::env::var("EDAMAME_SERVER_KEY").unwrap_or("".to_string());
        let client_ca_cert = std::env::var("EDAMAME_CLIENT_CA_PEM").unwrap_or("".to_string());

        // Decode the server certificate
        let cert_base64 = server_pem.to_string();
        let cert_decoded = general_purpose::STANDARD
            .decode(&cert_base64)
            .expect("Failed to decode server certificate");
        let cert =
            str::from_utf8(&cert_decoded).expect("Failed to convert server certificate to string");

        // Decode the server key
        let key_base64 = server_key.to_string();
        let key_decoded = general_purpose::STANDARD
            .decode(&key_base64)
            .expect("Failed to decode server key");
        let key = str::from_utf8(&key_decoded).expect("Failed to convert server key to string");

        // Decode the client CA certificate
        let ca_cert_base64 = client_ca_cert.to_string();
        let ca_cert_decoded = general_purpose::STANDARD
            .decode(&ca_cert_base64)
            .expect("Failed to decode client CA certificate");
        let ca_cert = str::from_utf8(&ca_cert_decoded)
            .expect("Failed to convert client CA certificate to string");
        let ca_certificate = Certificate::from_pem(ca_cert);

        // Create client identity
        let client_identity = Identity::from_pem(cert, key);

        // Create TLS config
        let _ = ClientTlsConfig::new()
            .domain_name("localhost")
            .ca_certificate(ca_certificate)
            .identity(client_identity);
    }

    #[tokio::test]
    async fn test_grpc_mtls_authentication() -> Result<()> {
        #[derive(Debug, Default)]
        pub struct MockHelper {}

        #[tonic::async_trait]
        impl EdamameHelper for MockHelper {
            async fn execute(
                &self,
                request: Request<HelperRequest>,
            ) -> std::result::Result<Response<HelperResponse>, Status> {
                debug!("Received request: {:?}", request);
                let req = request.into_inner();
                if req.ordertype == "utilityorder" && req.subordertype == "helper_check" {
                    Ok(Response::new(HelperResponse {
                        output: env!("CARGO_PKG_VERSION").to_string(),
                    }))
                } else {
                    Err(Status::unimplemented("Not implemented"))
                }
            }
        }

        // Get certificates and keys from environment variables
        let server_pem = std::env::var("EDAMAME_SERVER_PEM").expect("EDAMAME_SERVER_PEM not set");
        let server_key = std::env::var("EDAMAME_SERVER_KEY").expect("EDAMAME_SERVER_KEY not set");
        let client_ca_cert =
            std::env::var("EDAMAME_CLIENT_CA_PEM").expect("EDAMAME_CLIENT_CA_PEM not set");
        let ca_pem = std::env::var("EDAMAME_CA_PEM").expect("EDAMAME_CA_PEM not set");
        let client_pem = std::env::var("EDAMAME_CLIENT_PEM").expect("EDAMAME_CLIENT_PEM not set");
        let client_key = std::env::var("EDAMAME_CLIENT_KEY").expect("EDAMAME_CLIENT_KEY not set");

        // Decode Base64 to PEM
        let server_cert = general_purpose::STANDARD.decode(server_pem)?;
        let server_key = general_purpose::STANDARD.decode(server_key)?;
        let client_ca_cert = general_purpose::STANDARD.decode(client_ca_cert)?;
        let ca_cert = general_purpose::STANDARD.decode(ca_pem)?;
        let client_cert = general_purpose::STANDARD.decode(client_pem)?;
        let client_key = general_purpose::STANDARD.decode(client_key)?;

        // Convert to strings
        let server_cert = String::from_utf8(server_cert)?;
        let server_key = String::from_utf8(server_key)?;
        let client_ca_cert = String::from_utf8(client_ca_cert)?;
        let ca_cert = String::from_utf8(ca_cert)?;
        let client_cert = String::from_utf8(client_cert)?;
        let client_key = String::from_utf8(client_key)?;

        // Set up server
        let server_identity = Identity::from_pem(&server_cert, &server_key);
        let server_tls_config = ServerTlsConfig::new()
            .identity(server_identity)
            .client_ca_root(Certificate::from_pem(client_ca_cert));

        let addr = "[::1]:50051".parse::<SocketAddr>()?;
        let (tx, rx) = oneshot::channel();

        let server_future = Server::builder()
            .tls_config(server_tls_config)?
            .add_service(EdamameHelperServer::new(MockHelper::default()))
            .serve_with_shutdown(addr, async {
                rx.await.ok();
            });

        // Start server in a separate task
        tokio::spawn(async move {
            info!("Starting server on {:?}", addr);
            if let Err(e) = server_future.await {
                error!("Server error: {:?}", e);
            }
        });

        // Give the server a moment to start
        sleep(Duration::from_secs(1)).await;

        // Set up client
        let client_identity = Identity::from_pem(&client_cert, &client_key);
        let client_tls_config = ClientTlsConfig::new()
            .domain_name("localhost")
            .ca_certificate(Certificate::from_pem(ca_cert))
            .identity(client_identity);

        info!("Attempting to connect to server");
        let channel = match timeout(
            Duration::from_secs(5),
            Channel::from_static("https://[::1]:50051")
                .tls_config(client_tls_config)?
                .connect(),
        )
        .await
        {
            Ok(Ok(channel)) => channel,
            Ok(Err(e)) => return Err(anyhow!("Failed to connect to server: {:?}", e)),
            Err(_) => return Err(anyhow!("Timeout while connecting to server")),
        };

        let mut client = EdamameHelperClient::new(channel);

        // Make a request
        let request = tonic::Request::new(HelperRequest {
            ordertype: "utilityorder".to_string(),
            subordertype: "helper_check".to_string(),
            arg1: "".to_string(),
            arg2: "".to_string(),
            signature: "".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        });

        // Send the request and get the response
        info!("Sending request to server");
        let response = match timeout(Duration::from_secs(5), client.execute(request)).await {
            Ok(Ok(response)) => response,
            Ok(Err(e)) => return Err(anyhow!("Error executing request: {:?}", e)),
            Err(_) => return Err(anyhow!("Timeout while executing request")),
        };

        // Check the response
        let helper_version = response.into_inner().output;
        assert_eq!(helper_version, env!("CARGO_PKG_VERSION"));

        // Shutdown the server
        info!("Shutting down server");
        tx.send(()).unwrap();

        Ok(())
    }
}
