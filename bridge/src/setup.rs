//! The launch handoff: the JSON a game hands `rp_start`, resolved into the
//! credentials the client transport needs (identity, pinned trust, dial
//! addresses). Mirrors ShieldBattery's `netcode_v2/credentials.rs`, minus the
//! evidence provider (Hyperion's own relay/coordinator sets the evidence
//! policy, so no connection evidence is collected).

use std::net::SocketAddr;

use base64::prelude::{BASE64_STANDARD, Engine as _};
use rally_point_client::proto::token::SignedToken;
use rally_point_client::transport::rustls::pki_types::CertificateDer;
use rally_point_client::transport::rustls::RootCertStore;
use rally_point_client::Identity;
use serde::Deserialize;

/// The JSON shape `rp_start` consumes. Field names follow ShieldBattery's
/// `NetcodeV2ServerSetup` (app-side) so one launcher format serves both.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Setup {
    /// base64 of the coordinator-signed `SignedToken`.
    pub token: String,
    /// base64 of the client's PKCS#8 Ed25519 private key.
    pub client_private_key: String,
    pub home_relay: HomeRelay,
    /// The turn-pipe depth to seed at session start (the relay's minimum).
    pub initial_buffer_turns: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HomeRelay {
    #[serde(default)]
    pub relay_id: u64,
    /// `ip:port` candidates in dial-preference order.
    pub addrs: Vec<String>,
    /// TLS server name checked against the pinned certificate.
    pub server_name: String,
    /// base64 of the relay's leaf certificate (DER).
    pub cert: String,
}

/// Everything one session needs to dial: credentials, target, trust store.
pub struct Credentials {
    pub identity: Identity,
    pub addrs: Vec<SocketAddr>,
    pub server_name: String,
    pub relay_id: u64,
    pub roots: RootCertStore,
    pub initial_buffer: u32,
    /// This client's slot, decoded from the signed token (never from the JSON).
    pub local_slot: u32,
}

impl Setup {
    pub fn resolve(self) -> Result<Credentials, String> {
        let token_bytes = decode_base64(&self.token, "token")?;
        let token = SignedToken::decode(&token_bytes).map_err(|e| format!("token: {e:?}"))?;

        let key_bytes = decode_base64(&self.client_private_key, "clientPrivateKey")?;
        let identity = Identity::from_pkcs8(token, &key_bytes).map_err(|e| e.to_string())?;

        // Pin the home relay, and only the home relay. An empty or unparseable
        // cert set is an error, never a silently-empty store.
        let cert_der = decode_base64(&self.home_relay.cert, "relayCert")?;
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(cert_der))
            .map_err(|e| format!("relay cert: {e}"))?;

        let addrs = self
            .home_relay
            .addrs
            .iter()
            .map(|a| a.parse::<SocketAddr>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("relay address: {e}"))?;
        if addrs.is_empty() {
            return Err("relay listed no address".to_string());
        }

        let local_slot = u32::from(identity.token().claims.slot.0);

        Ok(Credentials {
            identity,
            addrs,
            server_name: self.home_relay.server_name,
            relay_id: self.home_relay.relay_id,
            roots,
            initial_buffer: self.initial_buffer_turns,
            local_slot,
        })
    }
}

fn decode_base64(value: &str, field: &'static str) -> Result<Vec<u8>, String> {
    BASE64_STANDARD
        .decode(value)
        .map_err(|_| format!("`{field}` was not valid base64"))
}
