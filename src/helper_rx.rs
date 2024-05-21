use base64::{engine::general_purpose, Engine as _};
use std::error::Error;
use std::net::SocketAddr;
use std::str;
use tokio::sync::oneshot;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Code, Request, Response, Status};
use tracing::{error, info, trace, warn};

use lazy_static::lazy_static;
// Tokio Mutex
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::helper_proto::*;
use crate::runner_cli::*;
use crate::threat::*;

use crate::helper_rx_utility::*;

use edamame_proto::edamame_helper_server::{EdamameHelper, EdamameHelperServer};
use edamame_proto::{HelperRequest, HelperResponse};

lazy_static! {
    pub static ref THREATS: Arc<Mutex<ThreatMetrics>> = Arc::new(Mutex::new(ThreatMetrics::new("")));
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
            error!("Error while executing order: {}", e);
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
    ) -> Result<(), Box<dyn Error>> {
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

        let server_future = Server::builder()
            .tls_config(tls)?
            .add_service(EdamameHelperServer::new(edamame_server))
            .serve(sock);

        tokio::select! {
            result = server_future => {
                match result {
                    Ok(_) => {
                        info!("EDAMAME Helper stopped");
                        Ok(())
                    }
                    Err(e) => {
                        error!("EDAMAME Helper server error: {}", e);
                        Err(Box::new(e))
                    }
                }
            }
            _ = rx => {
                info!("EDAMAME Helper gracefully shutting down");
                Ok(())
            }
        }
    }

    pub async fn stop_server(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        Ok(())
    }
}

// Receiving end of the order - the RPC server error handling requires Send + Sync...
pub async fn rpc_run(
    ordertype: &str,
    subordertype: &str,
    arg1: &str,
    arg2: &str,
    signature: &str,
    version: &str,
) -> Result<String, Box<dyn Error>> {
    // Force update if any of the key mandatory fields are empty - this would indicate a protocol error
    if version.is_empty() || ordertype.is_empty() {
        return order_error("order received with empty version of ordertype", true);
    }

    // Check the version - allow xx.yy.zz = xx.yy.ww
    let major_version = version.split('.').take(2).collect::<Vec<&str>>().join(".");
    let major_cargo_version = CARGO_PKG_VERSION
        .split('.')
        .take(2)
        .collect::<Vec<&str>>()
        .join(".");
    if major_version != major_cargo_version {
        return order_error(
            &format!(
                "order received with foundation major version mismatch - received {} != {}",
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
            trace!("Locking THREATS - start");
            let mut metrics = THREATS.lock().await;
            trace!("Locking THREATS - end");
            // Get a copy of the current signature
            let current_signature = metrics.signature.clone();
            // Force update if signature mismatch
            if signature != current_signature {
                info!(
                    "Signature mismatch current is: {}, received is: {}",
                    current_signature, signature
                );
                // Perform update
                let branch = BRANCH.lock().await.clone();
                match metrics.update("", &branch).await {
                    Ok(_) => {
                        info!(
                            "Updated model from backend successfully - new signature is: {}",
                            metrics.signature
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
            for m in &metrics.metrics {
                if m.metric.name == threat {
                    match subordertype {
                        "capture" => implementation = Some(&m.metric.implementation),
                        "remediate" => implementation = Some(&m.metric.remediation),
                        "rollback" => implementation = Some(&m.metric.rollback),
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
                Ok(CARGO_PKG_VERSION.to_string())
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

fn order_error(comment: &str, fatal: bool) -> Result<String, Box<dyn Error>> {
    let msg = if fatal {
        format!("Fatal order error : {}", comment)
    } else {
        format!("Order error : {}", comment)
    };

    error!("{}", msg);
    Err(From::from(msg))
}
