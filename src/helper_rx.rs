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
        // Configure HTTP/2 keep-alive to prevent connection drops during long operations
        // like get_sessions which can take 100+ seconds with large session counts.
        // Without these settings, the default hyper keep-alive timeout (20s) can cause
        // "Missing response message" errors.
        let server_future = match Server::builder()
            .http2_keepalive_interval(Some(std::time::Duration::from_secs(30)))
            .http2_keepalive_timeout(Some(std::time::Duration::from_secs(120)))
            .tls_config(tls)
        {
            Ok(mut builder) => builder
                .add_service(
                    EdamameHelperServer::new(edamame_server)
                        // For session data, the messages can be large
                        .max_decoding_message_size(1000 * 1024 * 1024)
                        .max_encoding_message_size(1000 * 1024 * 1024),
                )
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

    #[cfg(feature = "packetcapture")]
    use flodbadd::sessions::{
        DomainResolutionType, Protocol, Session, SessionInfo, SessionL7, SessionProcessDiskUsage,
        SessionStats, SessionStatus, WhitelistState,
    };

    /// Helper function to create a mock SessionInfo (using actual flodbadd types)
    #[cfg(feature = "packetcapture")]
    fn create_mock_session_info(id: usize) -> SessionInfo {
        use chrono::Utc;
        use std::net::{IpAddr, Ipv4Addr};

        let now = Utc::now();
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, (id % 256) as u8));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, (id % 256) as u8));

        SessionInfo {
            session: Session {
                protocol: Protocol::TCP,
                src_ip,
                src_port: (1024 + (id % 64000)) as u16,
                dst_ip,
                dst_port: 443,
            },
            status: SessionStatus {
                active: id % 2 == 0,
                added: true,
                activated: true,
                deactivated: id % 3 == 0,
            },
            stats: SessionStats {
                start_time: now,
                end_time: if id % 2 == 0 { None } else { Some(now) },
                last_activity: now,
                inbound_bytes: (id * 1000) as u64,
                outbound_bytes: (id * 500) as u64,
                orig_pkts: (id % 1000) as u64,
                resp_pkts: (id % 500) as u64,
                orig_ip_bytes: (id * 1200) as u64,
                resp_ip_bytes: (id * 600) as u64,
                history: "ShADadFf".to_string(),
                conn_state: Some("SF".to_string()),
                missed_bytes: 0,
                average_packet_size: 1400.0,
                inbound_outbound_ratio: 2.0,
                segment_count: (id % 10) as u32,
                current_segment_start: now,
                last_segment_end: None,
                segment_interarrival: 0.5,
                total_segment_interarrival: 5.0,
                in_segment: false,
                segment_timeout: 5.0,
            },
            is_local_src: true,
            is_local_dst: false,
            is_self_src: id % 10 == 0,
            is_self_dst: false,
            src_domain: None,
            dst_domain: Some(format!("example{}.com", id % 1000)),
            src_domain_type: DomainResolutionType::None,
            dst_domain_type: DomainResolutionType::Forward,
            dst_service: Some("https".to_string()),
            l7: Some(SessionL7 {
                pid: (1000 + id) as u32,
                process_name: format!("mock_process_{}", id % 100),
                process_path: format!("/usr/bin/mock_process_{}", id % 100),
                username: "testuser".to_string(),
                cmd: vec![format!("mock_process_{}", id % 100), "--arg".to_string()],
                cwd: Some("/home/testuser".to_string()),
                memory: 1024 * 1024 * (id % 100 + 1) as u64,
                start_time: now.timestamp() as u64,
                run_time: (id % 3600) as u64,
                cpu_usage: (id % 100) as u32,
                accumulated_cpu_time: (id * 1000) as u64,
                disk_usage: SessionProcessDiskUsage {
                    total_written_bytes: (id * 10000) as u64,
                    written_bytes: (id * 1000) as u64,
                    total_read_bytes: (id * 20000) as u64,
                    read_bytes: (id * 2000) as u64,
                },
                open_files: Some((id % 100) as u64),
            }),
            src_asn: None,
            dst_asn: None,
            is_whitelisted: if id % 5 == 0 {
                WhitelistState::Conforming
            } else {
                WhitelistState::Unknown
            },
            criticality: "low".to_string(),
            dismissed: false,
            whitelist_reason: if id % 5 == 0 {
                Some("Auto-whitelisted".to_string())
            } else {
                None
            },
            uid: format!("session-{}-{}", id, now.timestamp()),
            last_modified: now,
        }
    }

    /// Generate a large mock session payload using bincode + base64 (matching real format)
    #[cfg(feature = "packetcapture")]
    fn generate_bincode_session_payload(session_count: usize) -> String {
        let sessions: Vec<SessionInfo> = (0..session_count)
            .map(|i| create_mock_session_info(i))
            .collect();

        // Serialize with bincode (matching utility_get_sessions)
        let bincode_sessions =
            bincode::serde::encode_to_vec(&sessions, bincode::config::standard())
                .expect("Failed to encode sessions to bincode");

        // Base64 encode for transport
        general_purpose::STANDARD.encode(&bincode_sessions)
    }

    /// Fallback for non-packetcapture builds: generate fake base64 data
    #[cfg(not(feature = "packetcapture"))]
    fn generate_bincode_session_payload(session_count: usize) -> String {
        // Generate fake binary data that's approximately the right size
        // Real sessions are ~200-300 bytes each in bincode format
        let fake_data = vec![0u8; session_count * 250];
        general_purpose::STANDARD.encode(&fake_data)
    }

    /// Mock helper that handles various order types including large payload responses
    #[derive(Debug)]
    pub struct ComprehensiveMockHelper {
        /// Number of sessions to return for get_sessions
        session_count: usize,
        /// Simulate processing delay in milliseconds
        processing_delay_ms: u64,
        /// Whether to return errors for specific order types
        fail_orders: std::collections::HashSet<String>,
    }

    impl Default for ComprehensiveMockHelper {
        fn default() -> Self {
            Self {
                session_count: 100,
                processing_delay_ms: 0,
                fail_orders: std::collections::HashSet::new(),
            }
        }
    }

    impl ComprehensiveMockHelper {
        fn with_session_count(mut self, count: usize) -> Self {
            self.session_count = count;
            self
        }

        fn with_processing_delay(mut self, delay_ms: u64) -> Self {
            self.processing_delay_ms = delay_ms;
            self
        }

        fn with_failing_order(mut self, order: &str) -> Self {
            self.fail_orders.insert(order.to_string());
            self
        }
    }

    #[tonic::async_trait]
    impl EdamameHelper for ComprehensiveMockHelper {
        async fn execute(
            &self,
            request: Request<HelperRequest>,
        ) -> std::result::Result<Response<HelperResponse>, Status> {
            let req = request.into_inner();

            // Simulate processing delay if configured
            if self.processing_delay_ms > 0 {
                sleep(Duration::from_millis(self.processing_delay_ms)).await;
            }

            // Check if this order should fail
            let order_key = format!("{}:{}", req.ordertype, req.subordertype);
            if self.fail_orders.contains(&order_key) {
                return Err(Status::internal(format!(
                    "Simulated failure for {}",
                    order_key
                )));
            }

            match (req.ordertype.as_str(), req.subordertype.as_str()) {
                // Utility orders
                ("utilityorder", "helper_check") => Ok(Response::new(HelperResponse {
                    output: env!("CARGO_PKG_VERSION").to_string(),
                })),
                ("utilityorder", "get_sessions") => {
                    // Use bincode + base64 encoding (matching real implementation)
                    let payload = generate_bincode_session_payload(self.session_count);
                    Ok(Response::new(HelperResponse { output: payload }))
                }
                ("utilityorder", "get_current_sessions") => {
                    // Return a smaller subset for current sessions
                    let payload = generate_bincode_session_payload(self.session_count / 10);
                    Ok(Response::new(HelperResponse { output: payload }))
                }
                ("utilityorder", "get_whitelist_exceptions") => {
                    // Generate whitelist exceptions (similar structure to sessions)
                    let payload = generate_bincode_session_payload(self.session_count / 5);
                    Ok(Response::new(HelperResponse { output: payload }))
                }
                ("utilityorder", "get_blacklisted_sessions") => {
                    // Generate blacklisted sessions
                    let payload = generate_bincode_session_payload(self.session_count / 20);
                    Ok(Response::new(HelperResponse { output: payload }))
                }
                ("utilityorder", "get_packet_stats") => Ok(Response::new(HelperResponse {
                    output: r#"{"packets_captured":1000000,"packets_dropped":100,"bytes_captured":500000000}"#.to_string(),
                })),
                ("utilityorder", "get_whitelist_conformance") => Ok(Response::new(HelperResponse {
                    output: r#"{"conformant":95.5,"non_conformant":4.5}"#.to_string(),
                })),
                ("utilityorder", "get_filter") => Ok(Response::new(HelperResponse {
                    output: r#"{"active":true,"rules":["allow tcp any any"]}"#.to_string(),
                })),
                // Metric orders
                ("metricorder", "capture") => Ok(Response::new(HelperResponse {
                    output: "capture completed".to_string(),
                })),
                ("metricorder", "remediate") => Ok(Response::new(HelperResponse {
                    output: "remediation completed".to_string(),
                })),
                ("metricorder", "rollback") => Ok(Response::new(HelperResponse {
                    output: "rollback completed".to_string(),
                })),
                _ => Err(Status::unimplemented(format!(
                    "Not implemented: {} / {}",
                    req.ordertype, req.subordertype
                ))),
            }
        }
    }

    /// Helper to set up test server and return client configuration
    async fn setup_test_server(
        port: u16,
        mock_helper: ComprehensiveMockHelper,
    ) -> Result<(
        oneshot::Sender<()>,
        String,
        String,
        String,
        String,
        String,
        String,
    )> {
        // Get certificates from environment
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
        let client_key_env = std::env::var("EDAMAME_CLIENT_KEY")
            .expect("EDAMAME_CLIENT_KEY not set")
            .trim_matches('"')
            .to_string();

        // Decode certificates
        let server_cert = general_purpose::STANDARD.decode(&server_pem)?;
        let server_key_decoded = general_purpose::STANDARD.decode(&server_key)?;
        let client_ca_cert_decoded = general_purpose::STANDARD.decode(&client_ca_cert)?;

        let server_cert_str = String::from_utf8(server_cert)?;
        let server_key_str = String::from_utf8(server_key_decoded)?;
        let client_ca_cert_str = String::from_utf8(client_ca_cert_decoded)?;

        // Set up server TLS
        let server_identity = Identity::from_pem(&server_cert_str, &server_key_str);
        let server_tls_config = ServerTlsConfig::new()
            .identity(server_identity)
            .client_ca_root(Certificate::from_pem(&client_ca_cert_str));

        let addr = format!("[::1]:{}", port).parse::<SocketAddr>()?;
        let (tx, rx) = oneshot::channel();

        let server_future = Server::builder()
            .http2_keepalive_interval(Some(std::time::Duration::from_secs(30)))
            .http2_keepalive_timeout(Some(std::time::Duration::from_secs(120)))
            .tls_config(server_tls_config)?
            .add_service(
                EdamameHelperServer::new(mock_helper)
                    .max_decoding_message_size(1000 * 1024 * 1024)
                    .max_encoding_message_size(1000 * 1024 * 1024),
            )
            .serve_with_shutdown(addr, async {
                rx.await.ok();
            });

        tokio::spawn(async move {
            info!("Starting test server on {:?}", addr);
            if let Err(e) = server_future.await {
                error!("Test server error: {:?}", e);
            }
        });

        // Give the server time to start
        sleep(Duration::from_millis(500)).await;

        Ok((
            tx,
            ca_pem,
            client_pem,
            client_key_env,
            server_pem,
            server_key,
            client_ca_cert,
        ))
    }

    /// Helper to create a configured client
    async fn create_test_client(
        port: u16,
        ca_pem: &str,
        client_pem: &str,
        client_key: &str,
    ) -> Result<EdamameHelperClient<Channel>> {
        let ca_cert = general_purpose::STANDARD.decode(ca_pem)?;
        let client_cert = general_purpose::STANDARD.decode(client_pem)?;
        let client_key_decoded = general_purpose::STANDARD.decode(client_key)?;

        let ca_cert_str = String::from_utf8(ca_cert)?;
        let client_cert_str = String::from_utf8(client_cert)?;
        let client_key_str = String::from_utf8(client_key_decoded)?;

        let client_identity = Identity::from_pem(&client_cert_str, &client_key_str);
        let client_tls_config = ClientTlsConfig::new()
            .domain_name("localhost")
            .ca_certificate(Certificate::from_pem(&ca_cert_str))
            .identity(client_identity);

        let endpoint = format!("https://[::1]:{}", port);
        let channel = Channel::from_shared(endpoint)?
            .tls_config(client_tls_config)?
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(120))
            .keep_alive_while_idle(true)
            .connect()
            .await?;

        Ok(EdamameHelperClient::new(channel)
            .max_decoding_message_size(1000 * 1024 * 1024)
            .max_encoding_message_size(1000 * 1024 * 1024))
    }

    #[tokio::test]
    async fn test_large_session_payload_10k_sessions() -> Result<()> {
        use crate::admin::get_admin_status;

        if get_admin_status() {
            println!("Skipping test because running as admin");
            return Ok(());
        }

        const SESSION_COUNT: usize = 10_000;
        const TEST_PORT: u16 = 50052;

        let mock_helper = ComprehensiveMockHelper::default().with_session_count(SESSION_COUNT);

        let (shutdown_tx, ca_pem, client_pem, client_key, _, _, _) =
            setup_test_server(TEST_PORT, mock_helper).await?;

        let mut client = create_test_client(TEST_PORT, &ca_pem, &client_pem, &client_key).await?;

        // Request get_sessions
        let request = tonic::Request::new(HelperRequest {
            ordertype: "utilityorder".to_string(),
            subordertype: "get_sessions".to_string(),
            arg1: "false".to_string(),
            arg2: "".to_string(),
            signature: "".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        });

        info!(
            "Sending get_sessions request for {} sessions",
            SESSION_COUNT
        );
        let start = std::time::Instant::now();
        let response = timeout(Duration::from_secs(60), client.execute(request)).await??;
        let elapsed = start.elapsed();

        let output = response.into_inner().output;
        let payload_size = output.len();

        info!(
            "Received {} base64 bytes in {:?} ({:.2} MB)",
            payload_size,
            elapsed,
            payload_size as f64 / 1_000_000.0
        );

        // Verify we got valid base64 (bincode sessions are base64 encoded)
        let decoded = general_purpose::STANDARD
            .decode(&output)
            .expect("Response should be valid base64");
        info!(
            "Decoded to {} bincode bytes ({:.2} MB)",
            decoded.len(),
            decoded.len() as f64 / 1_000_000.0
        );

        // Verify we can decode the bincode payload back to sessions
        #[cfg(feature = "packetcapture")]
        {
            let sessions: Vec<SessionInfo> =
                bincode::serde::decode_from_slice(&decoded, bincode::config::standard())
                    .expect("Should decode bincode sessions")
                    .0;
            assert_eq!(
                sessions.len(),
                SESSION_COUNT,
                "Should have {} sessions",
                SESSION_COUNT
            );
            info!("Successfully decoded {} sessions", sessions.len());
        }

        // Verify approximate payload size (bincode is ~200-350 bytes per session, then base64 adds ~33%)
        // So base64 size should be roughly session_count * 300 * 1.33 = session_count * 400
        assert!(
            payload_size > SESSION_COUNT * 200,
            "Payload too small: {} bytes for {} sessions",
            payload_size,
            SESSION_COUNT
        );

        shutdown_tx.send(()).ok();
        Ok(())
    }

    #[tokio::test]
    async fn test_large_session_payload_50k_sessions() -> Result<()> {
        use crate::admin::get_admin_status;

        if get_admin_status() {
            println!("Skipping test because running as admin");
            return Ok(());
        }

        const SESSION_COUNT: usize = 50_000;
        const TEST_PORT: u16 = 50053;

        let mock_helper = ComprehensiveMockHelper::default().with_session_count(SESSION_COUNT);

        let (shutdown_tx, ca_pem, client_pem, client_key, _, _, _) =
            setup_test_server(TEST_PORT, mock_helper).await?;

        let mut client = create_test_client(TEST_PORT, &ca_pem, &client_pem, &client_key).await?;

        let request = tonic::Request::new(HelperRequest {
            ordertype: "utilityorder".to_string(),
            subordertype: "get_sessions".to_string(),
            arg1: "false".to_string(),
            arg2: "".to_string(),
            signature: "".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        });

        info!(
            "Sending get_sessions request for {} sessions",
            SESSION_COUNT
        );
        let start = std::time::Instant::now();
        let response = timeout(Duration::from_secs(120), client.execute(request)).await??;
        let elapsed = start.elapsed();

        let output = response.into_inner().output;
        let payload_size = output.len();

        info!(
            "Received {} base64 bytes in {:?} ({:.2} MB)",
            payload_size,
            elapsed,
            payload_size as f64 / 1_000_000.0
        );

        // Decode base64 to verify it's valid
        let _ = general_purpose::STANDARD
            .decode(&output)
            .expect("Response should be valid base64");

        // Verify we can decode the bincode payload back to sessions
        #[cfg(feature = "packetcapture")]
        {
            let sessions: Vec<SessionInfo> =
                bincode::serde::decode_from_slice(&decoded, bincode::config::standard())
                    .expect("Should decode bincode sessions")
                    .0;
            assert_eq!(
                sessions.len(),
                SESSION_COUNT,
                "Should have {} sessions",
                SESSION_COUNT
            );
        }

        // Verify payload size (50k sessions * ~300 bytes bincode * 1.33 base64 overhead = ~20MB)
        assert!(
            payload_size > 10_000_000,
            "Payload too small for 50k sessions: {} bytes",
            payload_size
        );

        shutdown_tx.send(()).ok();
        Ok(())
    }

    #[tokio::test]
    async fn test_large_session_payload_1m_sessions() -> Result<()> {
        use crate::admin::get_admin_status;

        if get_admin_status() {
            println!("Skipping test because running as admin");
            return Ok(());
        }

        const SESSION_COUNT: usize = 1_000_000;
        const TEST_PORT: u16 = 50059;

        println!("Starting 1M session test - this will generate ~300-400MB payload");

        let mock_helper = ComprehensiveMockHelper::default().with_session_count(SESSION_COUNT);

        let (shutdown_tx, ca_pem, client_pem, client_key, _, _, _) =
            setup_test_server(TEST_PORT, mock_helper).await?;

        let mut client = create_test_client(TEST_PORT, &ca_pem, &client_pem, &client_key).await?;

        let request = tonic::Request::new(HelperRequest {
            ordertype: "utilityorder".to_string(),
            subordertype: "get_sessions".to_string(),
            arg1: "false".to_string(),
            arg2: "".to_string(),
            signature: "".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        });

        println!(
            "Sending get_sessions request for {} sessions",
            SESSION_COUNT
        );
        let start = std::time::Instant::now();
        // Allow up to 5 minutes for 1M sessions
        let response = timeout(Duration::from_secs(300), client.execute(request)).await??;
        let elapsed = start.elapsed();

        let output = response.into_inner().output;
        let payload_size = output.len();

        println!(
            "Received {} base64 bytes in {:?} ({:.2} MB, {:.2} MB/s)",
            payload_size,
            elapsed,
            payload_size as f64 / 1_000_000.0,
            payload_size as f64 / 1_000_000.0 / elapsed.as_secs_f64()
        );

        // Decode base64 to verify it's valid
        let decode_start = std::time::Instant::now();
        let decoded = general_purpose::STANDARD
            .decode(&output)
            .expect("Response should be valid base64");
        let decode_elapsed = decode_start.elapsed();

        println!(
            "Decoded to {} bincode bytes ({:.2} MB) in {:?}",
            decoded.len(),
            decoded.len() as f64 / 1_000_000.0,
            decode_elapsed
        );

        // Verify we can decode the bincode payload back to sessions
        #[cfg(feature = "packetcapture")]
        {
            let bincode_start = std::time::Instant::now();
            let sessions: Vec<SessionInfo> =
                bincode::serde::decode_from_slice(&decoded, bincode::config::standard())
                    .expect("Should decode bincode sessions")
                    .0;
            let bincode_elapsed = bincode_start.elapsed();

            println!(
                "Decoded {} sessions from bincode in {:?}",
                sessions.len(),
                bincode_elapsed
            );

            assert_eq!(
                sessions.len(),
                SESSION_COUNT,
                "Should have {} sessions",
                SESSION_COUNT
            );
        }

        // Verify payload size (1M sessions * ~300 bytes bincode * 1.33 base64 overhead = ~400MB)
        assert!(
            payload_size > 200_000_000,
            "Payload too small for 1M sessions: {} bytes ({:.2} MB)",
            payload_size,
            payload_size as f64 / 1_000_000.0
        );

        println!(
            "1M session test completed successfully: {:.2} MB transferred in {:?}",
            payload_size as f64 / 1_000_000.0,
            elapsed
        );

        shutdown_tx.send(()).ok();
        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_order_types() -> Result<()> {
        use crate::admin::get_admin_status;

        if get_admin_status() {
            println!("Skipping test because running as admin");
            return Ok(());
        }

        const TEST_PORT: u16 = 50054;

        let mock_helper = ComprehensiveMockHelper::default().with_session_count(100);

        let (shutdown_tx, ca_pem, client_pem, client_key, _, _, _) =
            setup_test_server(TEST_PORT, mock_helper).await?;

        let mut client = create_test_client(TEST_PORT, &ca_pem, &client_pem, &client_key).await?;

        // Test utility orders
        let utility_orders = vec![
            ("helper_check", env!("CARGO_PKG_VERSION")),
            ("get_packet_stats", "packets_captured"),
            ("get_whitelist_conformance", "conformant"),
            ("get_filter", "active"),
        ];

        for (suborder, expected_content) in utility_orders {
            let request = tonic::Request::new(HelperRequest {
                ordertype: "utilityorder".to_string(),
                subordertype: suborder.to_string(),
                arg1: "".to_string(),
                arg2: "".to_string(),
                signature: "".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            });

            let response = client.execute(request).await?;
            let output = response.into_inner().output;
            assert!(
                output.contains(expected_content),
                "Order {} should contain '{}', got: {}",
                suborder,
                expected_content,
                output
            );
            info!("Order {} passed", suborder);
        }

        // Test metric orders
        let metric_orders = vec![
            ("capture", "capture completed"),
            ("remediate", "remediation completed"),
            ("rollback", "rollback completed"),
        ];

        for (suborder, expected_content) in metric_orders {
            let request = tonic::Request::new(HelperRequest {
                ordertype: "metricorder".to_string(),
                subordertype: suborder.to_string(),
                arg1: "test_threat".to_string(),
                arg2: "test_user".to_string(),
                signature: "test_sig".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            });

            let response = client.execute(request).await?;
            let output = response.into_inner().output;
            assert!(
                output.contains(expected_content),
                "Order {} should contain '{}', got: {}",
                suborder,
                expected_content,
                output
            );
            info!("Metric order {} passed", suborder);
        }

        shutdown_tx.send(()).ok();
        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_large_requests() -> Result<()> {
        use crate::admin::get_admin_status;

        if get_admin_status() {
            println!("Skipping test because running as admin");
            return Ok(());
        }

        const SESSION_COUNT: usize = 5_000;
        const TEST_PORT: u16 = 50055;
        const CONCURRENT_REQUESTS: usize = 5;

        let mock_helper = ComprehensiveMockHelper::default().with_session_count(SESSION_COUNT);

        let (shutdown_tx, ca_pem, client_pem, client_key, _, _, _) =
            setup_test_server(TEST_PORT, mock_helper).await?;

        // Create multiple clients for concurrent requests
        let mut handles = Vec::new();

        for i in 0..CONCURRENT_REQUESTS {
            let ca = ca_pem.clone();
            let client = client_pem.clone();
            let key = client_key.clone();

            let handle = tokio::spawn(async move {
                let mut grpc_client = create_test_client(TEST_PORT, &ca, &client, &key).await?;

                let request = tonic::Request::new(HelperRequest {
                    ordertype: "utilityorder".to_string(),
                    subordertype: "get_sessions".to_string(),
                    arg1: "false".to_string(),
                    arg2: "".to_string(),
                    signature: "".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                });

                let start = std::time::Instant::now();
                let response = grpc_client.execute(request).await?;
                let elapsed = start.elapsed();

                let output = response.into_inner().output;
                info!(
                    "Concurrent request {} completed: {} bytes in {:?}",
                    i,
                    output.len(),
                    elapsed
                );

                Ok::<_, anyhow::Error>(output.len())
            });

            handles.push(handle);
        }

        // Wait for all requests to complete
        let results: Vec<_> = futures::future::join_all(handles).await;

        for (i, result) in results.iter().enumerate() {
            match result {
                Ok(Ok(size)) => {
                    // Bincode + base64 is more compact: ~200-350 bytes per session in bincode,
                    // then ~33% overhead for base64, so roughly 300-450 bytes per session in base64
                    assert!(
                        *size > SESSION_COUNT * 200,
                        "Request {} returned insufficient data: {} bytes for {} sessions",
                        i,
                        size,
                        SESSION_COUNT
                    );
                }
                Ok(Err(e)) => panic!("Request {} failed: {:?}", i, e),
                Err(e) => panic!("Request {} task failed: {:?}", i, e),
            }
        }

        shutdown_tx.send(()).ok();
        Ok(())
    }

    #[tokio::test]
    async fn test_order_error_handling() -> Result<()> {
        use crate::admin::get_admin_status;

        if get_admin_status() {
            println!("Skipping test because running as admin");
            return Ok(());
        }

        const TEST_PORT: u16 = 50056;

        let mock_helper = ComprehensiveMockHelper::default()
            .with_session_count(100)
            .with_failing_order("utilityorder:get_sessions");

        let (shutdown_tx, ca_pem, client_pem, client_key, _, _, _) =
            setup_test_server(TEST_PORT, mock_helper).await?;

        let mut client = create_test_client(TEST_PORT, &ca_pem, &client_pem, &client_key).await?;

        // Test that get_sessions fails as configured
        let request = tonic::Request::new(HelperRequest {
            ordertype: "utilityorder".to_string(),
            subordertype: "get_sessions".to_string(),
            arg1: "false".to_string(),
            arg2: "".to_string(),
            signature: "".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        });

        let result = client.execute(request).await;
        assert!(result.is_err(), "Expected get_sessions to fail");
        let err = result.unwrap_err();
        assert!(
            err.message().contains("Simulated failure"),
            "Expected simulated failure message, got: {}",
            err.message()
        );

        // Test that other orders still work
        let request = tonic::Request::new(HelperRequest {
            ordertype: "utilityorder".to_string(),
            subordertype: "helper_check".to_string(),
            arg1: "".to_string(),
            arg2: "".to_string(),
            signature: "".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        });

        let response = client.execute(request).await?;
        assert_eq!(
            response.into_inner().output,
            env!("CARGO_PKG_VERSION").to_string()
        );

        shutdown_tx.send(()).ok();
        Ok(())
    }

    #[tokio::test]
    async fn test_unimplemented_order() -> Result<()> {
        use crate::admin::get_admin_status;

        if get_admin_status() {
            println!("Skipping test because running as admin");
            return Ok(());
        }

        const TEST_PORT: u16 = 50057;

        let mock_helper = ComprehensiveMockHelper::default();

        let (shutdown_tx, ca_pem, client_pem, client_key, _, _, _) =
            setup_test_server(TEST_PORT, mock_helper).await?;

        let mut client = create_test_client(TEST_PORT, &ca_pem, &client_pem, &client_key).await?;

        // Test unimplemented order
        let request = tonic::Request::new(HelperRequest {
            ordertype: "utilityorder".to_string(),
            subordertype: "nonexistent_order".to_string(),
            arg1: "".to_string(),
            arg2: "".to_string(),
            signature: "".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        });

        let result = client.execute(request).await;
        assert!(result.is_err(), "Expected unimplemented order to fail");
        let err = result.unwrap_err();
        assert_eq!(
            err.code(),
            tonic::Code::Unimplemented,
            "Expected Unimplemented status"
        );

        shutdown_tx.send(()).ok();
        Ok(())
    }

    #[tokio::test]
    async fn test_processing_delay_with_large_payload() -> Result<()> {
        use crate::admin::get_admin_status;

        if get_admin_status() {
            println!("Skipping test because running as admin");
            return Ok(());
        }

        const SESSION_COUNT: usize = 1_000;
        const TEST_PORT: u16 = 50058;
        const DELAY_MS: u64 = 2000; // 2 second delay

        let mock_helper = ComprehensiveMockHelper::default()
            .with_session_count(SESSION_COUNT)
            .with_processing_delay(DELAY_MS);

        let (shutdown_tx, ca_pem, client_pem, client_key, _, _, _) =
            setup_test_server(TEST_PORT, mock_helper).await?;

        let mut client = create_test_client(TEST_PORT, &ca_pem, &client_pem, &client_key).await?;

        let request = tonic::Request::new(HelperRequest {
            ordertype: "utilityorder".to_string(),
            subordertype: "get_sessions".to_string(),
            arg1: "false".to_string(),
            arg2: "".to_string(),
            signature: "".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        });

        let start = std::time::Instant::now();
        let response = timeout(Duration::from_secs(30), client.execute(request)).await??;
        let elapsed = start.elapsed();

        // Verify the delay was applied
        assert!(
            elapsed.as_millis() >= DELAY_MS as u128,
            "Expected at least {}ms delay, got {:?}",
            DELAY_MS,
            elapsed
        );

        let output = response.into_inner().output;
        // Verify it's valid base64
        let decoded = general_purpose::STANDARD
            .decode(&output)
            .expect("Response should be valid base64");

        info!(
            "Request with {}ms delay completed in {:?}, base64: {} bytes, bincode: {} bytes",
            DELAY_MS,
            elapsed,
            output.len(),
            decoded.len()
        );

        shutdown_tx.send(()).ok();
        Ok(())
    }
}
