use crate::helper_proto::*;
use crate::helper_rx_utility::*;
use crate::runner_cli::*;
use crate::threat_factory::*;
use crate::version::Version;
use anyhow::{anyhow, Error, Result};
use base64::engine::general_purpose;
use base64::Engine;
use edamame_proto::edamame_helper_server::{EdamameHelper, EdamameHelperServer};
use edamame_proto::{HelperRequest, HelperResponse};
use lazy_static::lazy_static;
use std::net::SocketAddr;
use std::str;
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::sync::Mutex;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Code, Request, Response, Status};
use tracing::{error, info, trace, warn};

lazy_static! {
    // Branch name
    pub static ref BRANCH: Arc<Mutex<String>> = Arc::new(Mutex::new("".to_string()));
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

pub fn order_error(comment: &str, fatal: bool) -> Result<String> {
    let msg = if fatal {
        format!("Fatal order error : {}", comment)
    } else {
        format!("Order error : {}", comment)
    };
    error!("{}", msg);
    Err(Error::msg(msg))
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
    let version_semver = match Version::parse(&version) {
        Ok(semver) => semver,
        Err(e) => {
            return order_error(&format!("invalid version format: {}", e), true);
        }
    };
    let cargo_semver = match Version::parse(&CARGO_PKG_VERSION) {
        Ok(semver) => semver,
        Err(e) => {
            return order_error(&format!("invalid version format: {}", e), true);
        }
    };
    // Don't account for patch versions (set them to 0)
    let version_semver = Version::new(version_semver.major, version_semver.minor, 0);
    let cargo_semver = Version::new(cargo_semver.major, cargo_semver.minor, 0);
    if version_semver > cargo_semver {
        return order_error(
            &format!(
                "order received with foundation major/minor version mismatch - received {} > {}",
                version, CARGO_PKG_VERSION
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
            let metrics = &THREATS;
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
                match update(&branch, false, "").await {
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
                    // Only apply to admin elevation
                    let personate = &implementation_clone.elevation == "admin";
                    trace!("Running target {} and class {}", target, class);
                    if !class.is_empty() {
                        return if personate && username.is_empty() {
                            order_error(&format!("personate required but no username provided for metricorder {}", threat), false)
                        } else {
                            match class {
                                "cli" => run_cli(target, username, personate, None).await,
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
            "getappleid_email" => utility_getappleid_email(arg1).await,
            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "packetcapture"
            ))]
            "get_peer_ids" => utility_get_peer_ids(arg1).await,
            "mdns_resolve" => utility_mdns_resolve(arg1).await,
            "arp_resolve" => utility_arp_resolve(arg1).await,
            "broadcast_ping" => utility_broadcast_ping(arg1).await,
            "get_neighbors" => utility_get_neighbors(arg1).await,
            "helper_check" => utility_helper_check().await,
            "helper_flags" => utility_helper_flags().await,
            "get_logs" => utility_get_logs().await,

            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "packetcapture"
            ))]
            "start_capture" => utility_start_capture().await,
            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "packetcapture"
            ))]
            "stop_capture" => utility_stop_capture().await,
            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "packetcapture"
            ))]
            "restart_capture" => utility_restart_capture().await,
            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "packetcapture"
            ))]
            "is_capturing" => utility_is_capturing().await,
            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "packetcapture"
            ))]
            "set_whitelist" => utility_set_whitelist(arg1).await,
            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "packetcapture"
            ))]
            "create_custom_whitelists" => utility_create_custom_whitelists().await,
            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "packetcapture"
            ))]
            "set_custom_whitelists" => utility_set_custom_whitelists(arg1).await,
            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "packetcapture"
            ))]
            "augment_custom_whitelists" => {
                // Convert tuple (String, f64) -> JSON string for transport
                match utility_augment_custom_whitelists().await {
                    Ok(result) => match serde_json::to_string(&result) {
                        Ok(json) => Ok(json),
                        Err(e) => order_error(
                            &format!("failed to serialize augment result: {}", e),
                            false,
                        ),
                    },
                    Err(e) => {
                        order_error(&format!("error augmenting custom whitelists: {}", e), false)
                    }
                }
            }
            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "packetcapture"
            ))]
            "merge_custom_whitelists" => utility_merge_custom_whitelists(arg1, arg2).await,
            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "packetcapture"
            ))]
            "compare_custom_whitelists" => {
                match utility_compare_custom_whitelists(arg1, arg2).await {
                    Ok(diff_percentage) => Ok(diff_percentage.to_string()),
                    Err(e) => {
                        order_error(&format!("error comparing custom whitelists: {}", e), false)
                    }
                }
            }
            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "packetcapture"
            ))]
            "set_custom_blacklists" => utility_set_custom_blacklists(arg1).await,
            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "packetcapture"
            ))]
            "set_filter" => utility_set_filter(arg1).await,
            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "packetcapture"
            ))]
            "get_filter" => utility_get_filter().await,
            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "packetcapture"
            ))]
            "get_sessions" => {
                let incremental: bool = serde_json::from_str(arg1).unwrap_or(false);
                utility_get_sessions(incremental).await
            }
            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "packetcapture"
            ))]
            "get_current_sessions" => {
                let incremental: bool = serde_json::from_str(arg1).unwrap_or(false);
                utility_get_current_sessions(incremental).await
            }
            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "packetcapture"
            ))]
            "get_packet_stats" => utility_get_packet_stats().await,
            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "packetcapture"
            ))]
            "get_whitelist_conformance" => utility_get_whitelist_conformance().await,
            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "packetcapture"
            ))]
            "get_whitelist_exceptions" => {
                let incremental: bool = serde_json::from_str(arg1).unwrap_or(false);
                utility_get_whitelist_exceptions(incremental).await
            }
            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "packetcapture"
            ))]
            "get_whitelists" => utility_get_whitelists().await,
            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "packetcapture"
            ))]
            "get_blacklists" => utility_get_blacklists().await,
            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "packetcapture"
            ))]
            "get_blacklisted_status" => utility_get_blacklisted_status().await,
            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "packetcapture"
            ))]
            "get_blacklisted_sessions" => {
                let incremental: bool = serde_json::from_str(arg1).unwrap_or(false);
                utility_get_blacklisted_sessions(incremental).await
            }
            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "packetcapture"
            ))]
            "get_whitelist_name" => utility_get_whitelist_name().await,
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
        let server_pem = std::env::var("EDAMAME_SERVER_PEM")
            .unwrap_or("".to_string())
            .trim_matches('"')
            .to_string();
        let server_key = std::env::var("EDAMAME_SERVER_KEY")
            .unwrap_or("".to_string())
            .trim_matches('"')
            .to_string();
        let client_ca_cert = std::env::var("EDAMAME_CLIENT_CA_PEM")
            .unwrap_or("".to_string())
            .trim_matches('"')
            .to_string();

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
        use crate::admin::get_admin_status;

        // Skip test if running as admin
        if get_admin_status() {
            println!("Skipping test_grpc_mtls_authentication test because running as admin");
            return Ok(());
        }

        #[derive(Debug, Default)]
        pub struct MockHelper {}

        #[tonic::async_trait]
        impl EdamameHelper for MockHelper {
            async fn execute(
                &self,
                request: Request<HelperRequest>,
            ) -> std::result::Result<Response<HelperResponse>, Status> {
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
        let server_pem = std::env::var("EDAMAME_SERVER_PEM")
            .expect("EDAMAME_SERVER_PEM not set")
            .trim_matches('"')
            .to_string();
        let server_key = std::env::var("EDAMAME_SERVER_KEY")
            .expect("EDAMAME_SERVER_KEY not set")
            .trim_matches('"')
            .to_string();
        let client_ca_cert = std::env::var("EDAMAME_CLIENT_CA_PEM")
            .expect("EDAMAME_CLIENT_CA_PEM not set")
            .trim_matches('"')
            .to_string();
        let ca_pem = std::env::var("EDAMAME_CA_PEM")
            .expect("EDAMAME_CA_PEM not set")
            .trim_matches('"')
            .to_string();
        let client_pem = std::env::var("EDAMAME_CLIENT_PEM")
            .expect("EDAMAME_CLIENT_PEM not set")
            .trim_matches('"')
            .to_string();
        let client_key = std::env::var("EDAMAME_CLIENT_KEY")
            .expect("EDAMAME_CLIENT_KEY not set")
            .trim_matches('"')
            .to_string();

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
