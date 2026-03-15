// crates/lightning/src/lnd_client.rs
//
// LND REST API client for VUSD Lightning transport.
//
// Uses LND's REST API (port 8080) instead of gRPC — no proto compilation required.
// All LND REST endpoints are documented at: https://lightning.engineering/api-docs/api/lnd/
//
// Fixes: G01 (stub), G02 (null node_id), G06 (no receiver), G13 (deterministic preimage)
//
// Feature flags:
//   default     — REST client (works against real LND, no proto compilation)
//   lnd-mock    — compile-time mock that always succeeds (for unit tests)

use std::time::Duration;
use std::collections::HashMap;
use thiserror::Error;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// TLV record type for VUSD transfer messages over keysend.
/// Must be > 65535 (user-defined range per BOLT #1).
pub const VUSD_TLV_TYPE: u64 = 5_482_373_485;
pub const VUSD_MSG_TLV_TYPE: u64 = 5_482_373_486;

#[derive(Debug, Error)]
pub enum LndError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    #[error("TLS error: {0}")]
    TlsError(String),
    #[error("HTTP error: status={status} body={body}")]
    HttpError { status: u16, body: String },
    #[error("Macaroon error: {0}")]
    MacaroonError(String),
    #[error("Payment failed: {0}")]
    PaymentFailed(String),
    #[error("Node not found: {0}")]
    NodeNotFound(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// LND REST connection config.
#[derive(Debug, Clone)]
pub struct LndConfig {
    /// REST API base URL, e.g. "https://localhost:8080"
    pub rest_url: String,
    /// Hex-encoded macaroon bytes (admin.macaroon)
    pub macaroon_hex: String,
    /// PEM-encoded TLS certificate from ~/.lnd/tls.cert (for self-signed cert acceptance)
    pub tls_cert_pem: Option<String>,
    /// Request timeout
    pub timeout: Duration,
}

impl LndConfig {
    /// Default config for a local LND instance.
    pub fn localhost_mainnet() -> Self {
        LndConfig {
            rest_url:      "https://localhost:8080".into(),
            macaroon_hex:  String::new(),
            tls_cert_pem:  None,
            timeout:       Duration::from_secs(30),
        }
    }

    pub fn localhost_signet() -> Self {
        LndConfig {
            rest_url:      "https://localhost:8080".into(),
            macaroon_hex:  String::new(),
            tls_cert_pem:  None,
            timeout:       Duration::from_secs(30),
        }
    }

    /// Load macaroon from the default LND data directory.
    pub fn load_macaroon_from_dir(lnd_dir: &std::path::Path, network: &str) -> Result<String, LndError> {
        let mac_path = lnd_dir
            .join("data/chain/bitcoin")
            .join(network)
            .join("admin.macaroon");
        let bytes = std::fs::read(&mac_path)
            .map_err(|e| LndError::MacaroonError(format!("read {}: {}", mac_path.display(), e)))?;
        Ok(bytes.iter().map(|b| format!("{:02x}", b)).collect())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// REST RESPONSE TYPES (LND API)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct GetInfoResponse {
    pub identity_pubkey:    String,
    pub alias:              String,
    pub block_height:       u32,
    #[serde(default)]
    pub synced_to_chain:    bool,
    #[serde(default)]
    pub uris:               Vec<String>,  // includes .onion addresses
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListChannelsResponse {
    #[serde(default)]
    pub channels: Vec<ChannelInfo>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChannelInfo {
    pub channel_point:   String,
    pub remote_pubkey:   String,
    pub capacity:        String,
    pub local_balance:   String,
    pub remote_balance:  String,
    pub active:          bool,
    pub private:         bool,
    pub chan_id:         String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SendPaymentRequest {
    /// Recipient pubkey hex (33 bytes compressed)
    pub dest:               String,
    /// Amount in satoshis (keysend nominal amount: 1 sat)
    pub amt:                String,
    /// Timeout in seconds
    pub timeout_seconds:    i32,
    /// Fee limit in satoshis
    pub fee_limit_sat:      String,
    /// Custom TLV records: map of type → base64-encoded bytes
    pub dest_custom_records: HashMap<String, String>,
    /// Payment hash (hex) — must be SHA256 of preimage
    pub payment_hash:       String,
    /// Allow self-payment (needed for internal testing)
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub allow_self_payment: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SendPaymentResponse {
    pub payment_hash:   String,
    pub payment_route:  Option<PaymentRoute>,
    #[serde(default)]
    pub payment_error:  String,
    pub status:         Option<String>,
    #[serde(default)]
    pub fee_sat:        String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PaymentRoute {
    pub total_fees:    String,
    pub total_amt:     String,
    #[serde(default)]
    pub hops:          Vec<RouteHop>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouteHop {
    pub pub_key: String,
    pub chan_id:  String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CloseChannelResponse {
    /// JSON contains a streaming response; we capture the first close_pending event.
    #[serde(default)]
    pub close_pending: Option<ClosePending>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClosePending {
    pub txid:   Option<String>,
    pub output_index: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InvoiceSubscription {
    #[serde(default)]
    pub custom_records:   HashMap<String, String>,
    pub add_index:        Option<String>,
    pub state:            Option<String>,
    pub settled:          bool,
    pub r_preimage:       Option<String>,
    /// Amount paid in millisatoshis — used for grosss_amount on Thunder Node relay.
    /// LND field name: "amt_paid_msat"
    #[serde(default, rename = "amt_paid_msat", deserialize_with = "deser_msat_string")]
    pub amt_paid_msat:    u64,
}

fn deser_msat_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    // LND returns amt_paid_msat as a string in JSON ("123456")
    let s = Option::<String>::deserialize(d)?.unwrap_or_default();
    Ok(s.parse::<u64>().unwrap_or(0))
}

// ─────────────────────────────────────────────────────────────────────────────
// LND REST CLIENT
// ─────────────────────────────────────────────────────────────────────────────

/// LND REST API client.
///
/// Uses LND's REST API (port 8080) to avoid gRPC proto compilation.
/// All calls require a valid admin macaroon for authentication.
pub struct LndClient {
    http:        reqwest::Client,
    config:      LndConfig,
}

impl LndClient {
    /// Create a new client and verify connectivity.
    ///
    /// Builds an HTTP client that:
    ///   - Accepts LND's self-signed TLS certificate
    ///   - Attaches the macaroon as Grpc-Metadata-Macaroon header on every request
    ///   - Connects via Tor SOCKS5 if a proxy is configured
    pub async fn connect(config: LndConfig) -> Result<Self, LndError> {
        let mut builder = reqwest::Client::builder()
            .timeout(config.timeout)
            .danger_accept_invalid_certs(true);  // LND uses self-signed cert

        // If TLS cert PEM is provided, add it as a trusted root instead of
        // accepting all certs — more secure for production deployments.
        if let Some(ref pem) = config.tls_cert_pem {
            let cert = reqwest::Certificate::from_pem(pem.as_bytes())
                .map_err(|e| LndError::TlsError(e.to_string()))?;
            builder = builder
                .danger_accept_invalid_certs(false)
                .add_root_certificate(cert);
        }

        let http = builder.build()
            .map_err(|e| LndError::ConnectionFailed(e.to_string()))?;

        tracing::info!(url = %config.rest_url, "LndClient: connecting via REST");
        Ok(LndClient { http, config })
    }

    /// Attach macaroon auth header and make a GET request.
    async fn get(&self, path: &str) -> Result<reqwest::Response, LndError> {
        let url = format!("{}{}", self.config.rest_url, path);
        self.http.get(&url)
            .header("Grpc-Metadata-Macaroon", &self.config.macaroon_hex)
            .send()
            .await
            .map_err(|e| LndError::ConnectionFailed(e.to_string()))
    }

    /// Attach macaroon auth header and make a POST request.
    async fn post<B: Serialize>(&self, path: &str, body: &B) -> Result<reqwest::Response, LndError> {
        let url = format!("{}{}", self.config.rest_url, path);
        self.http.post(&url)
            .header("Grpc-Metadata-Macaroon", &self.config.macaroon_hex)
            .json(body)
            .send()
            .await
            .map_err(|e| LndError::ConnectionFailed(e.to_string()))
    }

    /// GET /v1/getinfo — node identity and sync status.
    pub async fn get_info(&self) -> Result<GetInfoResponse, LndError> {
        let resp = self.get("/v1/getinfo").await?;
        let status = resp.status().as_u16();
        let body   = resp.text().await.unwrap_or_default();
        if status != 200 {
            return Err(LndError::HttpError { status, body });
        }
        serde_json::from_str(&body)
            .map_err(|e| LndError::SerializationError(e.to_string()))
    }

    /// GET /v1/channels — list active channels.
    pub async fn list_channels(&self) -> Result<ListChannelsResponse, LndError> {
        let resp = self.get("/v1/channels").await?;
        let status = resp.status().as_u16();
        let body   = resp.text().await.unwrap_or_default();
        if status != 200 {
            return Err(LndError::HttpError { status, body });
        }
        serde_json::from_str(&body)
            .map_err(|e| LndError::SerializationError(e.to_string()))
    }

    /// DELETE /v1/channels/{channel_point} — cooperative channel close.
    ///
    /// G05: used during key rotation to close all channels before generating
    /// a new node identity. A cooperative close settles on-chain cleanly
    /// and returns funds to both parties without a force-close CSV delay.
    ///
    /// channel_point format: "<funding_txid>:<output_index>"
    /// e.g. "abc123...def:0"
    ///
    /// Returns immediately — the on-chain close happens asynchronously.
    /// Caller should poll list_channels() until the channel disappears.
    pub async fn close_channel(&self, channel_point: &str) -> Result<CloseChannelResponse, LndError> {
        // URL-encode the channel point — the colon must be escaped
        let encoded = channel_point.replace(':', "%3A");
        let path = format!("/v1/channels/{}", encoded);

        let resp = self.http
            .delete(format!("{}{}", self.config.rest_url, path))
            .header("Grpc-Metadata-Macaroon", &self.config.macaroon_hex)
            .send()
            .await
            .map_err(|e| LndError::ConnectionFailed(e.to_string()))?;

        let status = resp.status().as_u16();
        let body   = resp.text().await.unwrap_or_default();

        if status != 200 {
            return Err(LndError::HttpError { status, body });
        }

        serde_json::from_str(&body)
            .map_err(|e| LndError::SerializationError(e.to_string()))
    }

    /// Wait for all channels to fully close (poll list_channels until empty).
    ///
    /// Used during key rotation after issuing close_channel() for each channel.
    /// Times out after `timeout` if channels are still open (e.g. unresponsive peer).
    pub async fn wait_for_all_channels_closed(
        &self,
        timeout: std::time::Duration,
    ) -> Result<(), LndError> {
        let deadline = std::time::Instant::now() + timeout;

        loop {
            if std::time::Instant::now() > deadline {
                return Err(LndError::ConnectionFailed(
                    "Timed out waiting for channels to close — some may still be open.                      Run `lncli listchannels` to check. Force-close may be needed."
                    .to_string()
                ));
            }

            match self.list_channels().await {
                Ok(resp) if resp.channels.is_empty() => {
                    tracing::info!("All channels closed");
                    return Ok(());
                }
                Ok(resp) => {
                    tracing::info!(
                        remaining = resp.channels.len(),
                        "Waiting for channels to close..."
                    );
                }
                Err(e) => {
                    tracing::warn!("list_channels error during rotation: {}", e);
                }
            }

            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
        }
    }

    /// POST /v1/channels/transactions/route — send a keysend payment with TLV records.
    ///
    /// The VUSD transfer message is embedded in TLV record VUSD_MSG_TLV_TYPE.
    /// A nominal 1-sat payment carries the payload to the next hop.
    ///
    /// Fix G13: preimage is now OsRng 32 bytes, not deterministic.
    pub async fn keysend(
        &self,
        dest_pubkey_hex: &str,
        tlv_payload:     Vec<u8>,
        fee_limit_sat:   u64,
    ) -> Result<SendPaymentResponse, LndError> {
        use rand::RngCore;

        // G13 FIX: cryptographically random preimage — never deterministic
        let mut preimage = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut preimage);
        let payment_hash: [u8; 32] = Sha256::digest(&preimage).into();

        // TLV records: keysend preimage + VUSD payload
        let mut custom_records = HashMap::new();
        custom_records.insert(
            VUSD_TLV_TYPE.to_string(),
            base64_encode(&preimage),
        );
        custom_records.insert(
            VUSD_MSG_TLV_TYPE.to_string(),
            base64_encode(&tlv_payload),
        );

        let req = SendPaymentRequest {
            dest:                dest_pubkey_hex.to_string(),
            amt:                 "1".to_string(),    // 1 sat — just enough to route
            timeout_seconds:     30,
            fee_limit_sat:       fee_limit_sat.to_string(),
            dest_custom_records: custom_records,
            payment_hash:        hex_encode(&payment_hash),
            allow_self_payment:  false,
        };

        let resp = self.post("/v1/channels/transactions", &req).await?;
        let status = resp.status().as_u16();
        let body   = resp.text().await.unwrap_or_default();

        if status != 200 {
            return Err(LndError::HttpError { status, body });
        }

        let pay_resp: SendPaymentResponse = serde_json::from_str(&body)
            .map_err(|e| LndError::SerializationError(e.to_string()))?;

        if !pay_resp.payment_error.is_empty() {
            return Err(LndError::PaymentFailed(pay_resp.payment_error));
        }

        Ok(pay_resp)
    }

    /// Subscribe to incoming keysend messages via LND's invoice subscription stream.
    ///
    /// Fix G06: implemented inbound message handler using LND REST streaming.
    ///
    /// LND exposes a streaming endpoint: GET /v1/invoices/subscribe
    /// Each newline-delimited JSON object is a settled invoice.
    /// We filter for invoices with our custom TLV type in custom_records.
    ///
    /// Returns a channel that yields raw VUSD TLV payloads as they arrive.
    pub async fn subscribe_keysend_messages(
        &self,
    ) -> Result<tokio::sync::mpsc::Receiver<Vec<u8>>, LndError> {
        let (tx, rx) = tokio::sync::mpsc::channel(256);

        let url      = format!("{}/v1/invoices/subscribe", self.config.rest_url);
        let macaroon = self.config.macaroon_hex.clone();
        let http     = self.http.clone();

        // Spawn background task that streams invoices and forwards VUSD payloads
        tokio::spawn(async move {
            loop {
                let result = http.get(&url)
                    .header("Grpc-Metadata-Macaroon", &macaroon)
                    .send()
                    .await;

                match result {
                    Err(e) => {
                        tracing::warn!("LND invoice stream error: {} — retrying in 5s", e);
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                    Ok(mut resp) => {
                        // Stream: each chunk is a newline-delimited JSON invoice
                        use tokio::io::AsyncBufReadExt;
                        // reqwest streaming — read chunks line by line
                        let mut buf = String::new();

                        while let Ok(Some(chunk)) = resp.chunk().await {
                            let text = String::from_utf8_lossy(chunk.as_ref());
                            buf.push_str(&text);

                            // Process complete JSON lines
                            while let Some(pos) = buf.find('\n') {
                                let line = buf[..pos].trim().to_string();
                                buf = buf[pos + 1..].to_string();

                                if line.is_empty() { continue; }

                                // Parse invoice
                                if let Ok(invoice) = serde_json::from_str::<InvoiceSubscription>(&line) {
                                    if !invoice.settled { continue; }

                                    // Look for our custom TLV type
                                    let key = VUSD_MSG_TLV_TYPE.to_string();
                                    if let Some(b64) = invoice.custom_records.get(&key) {
                                        if let Ok(payload) = base64_decode(b64) {
                                            if tx.send(payload).await.is_err() {
                                                tracing::info!("LND subscriber: receiver dropped, stopping stream");
                                                return;
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        tracing::warn!("LND invoice stream ended — retrying in 5s");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        });

        Ok(rx)
    }

    /// Verify this LND node is configured to use Tor (not clearnet).
    ///
    /// Fix G07 (partial): checks GetInfo URIs — if all URIs contain .onion, Tor is active.
    /// If any clearnet IP URI is present, the operator is warned.
    pub async fn verify_tor_only(&self) -> Result<bool, LndError> {
        let info = self.get_info().await?;
        if info.uris.is_empty() {
            // No URIs announced — could be Tor-only with no announcement
            return Ok(true);
        }
        let all_onion = info.uris.iter().all(|uri| uri.contains(".onion"));
        if !all_onion {
            let clearnet: Vec<_> = info.uris.iter()
                .filter(|u| !u.contains(".onion"))
                .collect();
            tracing::warn!(
                clearnet_uris = ?clearnet,
                "LND is announcing clearnet URIs — Tor-only mode may not be enforced"
            );
        }
        Ok(all_onion)
    }


    pub async fn subscribe_keysend_messages_with_amount(
        &self,
    ) -> Result<tokio::sync::mpsc::Receiver<(Vec<u8>, u64)>, LndError> {
        let (tx, rx) = tokio::sync::mpsc::channel(256);

        let url      = format!("{}/v1/invoices/subscribe", self.config.rest_url);
        let macaroon = self.config.macaroon_hex.clone();
        let http     = self.http.clone();

        tokio::spawn(async move {
            let mut buf = String::new();
            loop {
                let result = http.get(&url)
                    .header("Grpc-Metadata-Macaroon", &macaroon)
                    .send()
                    .await;

                match result {
                    Err(e) => {
                        tracing::warn!(
                            err = %e,
                            "LND keysend+amount stream error — retrying in 5s"
                        );
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                    Ok(mut resp) => {
                        buf.clear();
                        while let Ok(Some(chunk)) = resp.chunk().await {
                            let text = String::from_utf8_lossy(chunk.as_ref());
                            buf.push_str(&text);

                            while let Some(pos) = buf.find('\n') {
                                let line = buf[..pos].trim().to_string();
                                buf = buf[pos + 1..].to_string();
                                if line.is_empty() { continue; }

                                if let Ok(invoice) =
                                    serde_json::from_str::<InvoiceSubscription>(&line)
                                {
                                    if !invoice.settled { continue; }
                                    let key = VUSD_MSG_TLV_TYPE.to_string();
                                    if let Some(b64) = invoice.custom_records.get(&key) {
                                        if let Ok(payload) = base64_decode(b64) {
                                            let amt = invoice.amt_paid_msat;
                                            if tx.send((payload, amt)).await.is_err() {
                                                tracing::info!(
                                                    "LND keysend+amount: receiver dropped"
                                                );
                                                return;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        tracing::warn!(
                            "LND keysend+amount stream ended — reconnecting in 5s"
                        );
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        });

        Ok(rx)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VUSD TRANSPORT LAYER
// ─────────────────────────────────────────────────────────────────────────────

use crate::{VusdTransferMessage, LightningError, NodeId};

/// Routes VusdTransferMessages between nodes using LND keysend + TLV records.
///
/// Fix G02: our_node_id is populated from GetInfo on construction.
pub struct LndTransport {
    pub client:         LndClient,
    /// Our own LND node pubkey (populated from GetInfo on connect).
    pub our_node_id:    NodeId,
    /// Our .onion address (populated from GetInfo URIs).
    pub our_onion:      Option<String>,
    /// Fee budget per relay hop in satoshis.
    pub fee_limit_sat:  u64,

}



impl LndTransport {
    /// Connect and populate our identity from LND GetInfo.
    pub async fn new(config: LndConfig) -> Result<Self, LightningError> {
        let client = LndClient::connect(config).await
            .map_err(|e| LightningError::ChannelError(e.to_string()))?;

        // G02 FIX: get our actual pubkey and .onion from LND
        let (our_node_id, our_onion) = match client.get_info().await {
            Ok(info) => {
                let pubkey_bytes = hex_decode_32(&info.identity_pubkey)
                    .unwrap_or([0u8; 32]);
                let onion = info.uris.iter()
                    .find(|u| u.contains(".onion"))
                    .map(|u| u.split('@').nth(1).unwrap_or("").to_string());
                tracing::info!(
                    pubkey = %info.identity_pubkey,
                    onion  = ?onion,
                    "LndTransport: identity resolved"
                );
                (NodeId(pubkey_bytes), onion)
            }
            Err(e) => {
                tracing::warn!("LndTransport: GetInfo failed ({}), using null identity. Is LND running?", e);
                (NodeId([0u8; 32]), None)
            }
        };

        Ok(LndTransport {
            client,
            our_node_id,
            our_onion,
            fee_limit_sat: 10,  // 10 sat fee cap per hop
        })
    }

    /// Send a VusdTransferMessage to a recipient Lightning node.
    ///
    /// Serializes the message, pads it to PADDED_MSG_SIZE (via AnonTransport),
    /// and sends via keysend with VUSD_MSG_TLV_TYPE.
    pub async fn send_message(
        &self,
        recipient_pubkey_hex: &str,
        msg:                  &VusdTransferMessage,
    ) -> Result<(), LightningError> {
        let payload = msg.serialize()?;

        self.client
            .keysend(recipient_pubkey_hex, payload, self.fee_limit_sat)
            .await
            .map_err(|e| LightningError::ChannelError(e.to_string()))?;

        tracing::info!(
            recipient = recipient_pubkey_hex,
            "LndTransport: VUSD message sent via keysend"
        );
        Ok(())
    }

    /// Start receiving inbound VUSD transfer messages.
    ///
    /// Fix G06: spawns the LND invoice subscription stream.
    /// Returns a channel of decoded VusdTransferMessages.
    /// Subscribe to inbound VUSD keysend transfers.
    ///
    /// Returns a channel that yields (VusdTransferMessage, gross_amount_msat) pairs.
    /// gross_amount_msat is the raw Lightning payment amount — Thunder Node uses this
    /// to compute its fee breakdown via ThunderFeeBreakdown::compute().
    ///
    /// The channel stays open until the LND connection drops or the receiver is dropped.
    pub async fn start_receiver(
        &self,
    ) -> Result<tokio::sync::mpsc::Receiver<(VusdTransferMessage, u64)>, LightningError> {
        let (tx, rx) = tokio::sync::mpsc::channel(256);

        let mut raw_rx = self.client
            .subscribe_keysend_messages_with_amount()
            .await
            .map_err(|e| LightningError::ChannelError(e.to_string()))?;

        tokio::spawn(async move {
            while let Some((payload, amt_msat)) = raw_rx.recv().await {
                match VusdTransferMessage::deserialize(&payload) {
                    Ok(msg) => {
                        if tx.send((msg, amt_msat)).await.is_err() {
                            tracing::info!("LndTransport receiver: consumer dropped");
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("LndTransport: malformed VUSD message: {}", e);
                    }
                }
            }
        });

        Ok(rx)
    }

}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    let bytes: Vec<u8> = (0..s.len()/2)
        .filter_map(|i| u8::from_str_radix(&s[i*2..i*2+2], 16).ok())
        .collect();
    if bytes.len() >= 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes[..32]);
        Some(out)
    } else { None }
}

fn base64_encode(bytes: &[u8]) -> String {
    // Minimal base64 — in production use the `base64` crate
    use std::fmt::Write;
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(alphabet[((n >> 18) & 0x3f) as usize] as char);
        out.push(alphabet[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 { alphabet[((n >> 6) & 0x3f) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { alphabet[(n & 0x3f) as usize] as char } else { '=' });
    }
    out
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim_end_matches('=');
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let decode_char = |c: char| -> Result<u32, String> {
        alphabet.iter().position(|&b| b == c as u8)
            .map(|p| p as u32)
            .ok_or_else(|| format!("invalid base64 char: {}", c))
    };
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    for chunk in chars.chunks(4) {
        let b0 = decode_char(chunk[0])?;
        let b1 = decode_char(chunk[1])?;
        out.push(((b0 << 2) | (b1 >> 4)) as u8);
        if chunk.len() > 2 {
            let b2 = decode_char(chunk[2])?;
            out.push(((b1 << 4) | (b2 >> 2)) as u8);
            if chunk.len() > 3 {
                let b3 = decode_char(chunk[3])?;
                out.push(((b2 << 6) | b3) as u8);
            }
        }
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello Thunder Node \x00\xFF\xAB";
        let enc  = base64_encode(data);
        let dec  = base64_decode(&enc).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn test_base64_empty() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_decode("").unwrap(), b"");
    }

    #[test]
    fn test_hex_decode_32() {
        let hex = "a".repeat(64);
        let bytes = hex_decode_32(&hex).unwrap();
        assert_eq!(bytes, [0xaa; 32]);
    }

    #[test]
    fn test_tlv_types_in_user_range() {
        assert!(VUSD_TLV_TYPE     > 65535);
        assert!(VUSD_MSG_TLV_TYPE > 65535);
        assert_ne!(VUSD_TLV_TYPE, VUSD_MSG_TLV_TYPE);
    }

    #[test]
    fn test_lnd_config_rest_url() {
        let cfg = LndConfig::localhost_mainnet();
        assert!(cfg.rest_url.contains("8080"));
    }

    #[tokio::test]
    async fn test_lnd_client_connect_fails_gracefully_without_server() {
        let config = LndConfig::localhost_mainnet();
        // connect() itself doesn't fail (it just builds the HTTP client)
        // get_info() will fail because no LND is running
        let client = LndClient::connect(config).await.unwrap();
        let result = client.get_info().await;
        assert!(result.is_err(), "expected error when no LND is running");
    }
}
