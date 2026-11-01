//! `rp_dev_setup` — the dev harness for running a standalone relay plus two
//! `ctest` clients on one machine. It has no place in a real launch flow
//! (there the coordinator mints tokens and hands out relay certs); it exists
//! so Phase 1 can exercise the whole seam without one.
//!
//! Subcommands:
//!
//! ```text
//! rp_dev_setup gen-cert --cert <file.pem> --key <file.pem>
//!     Generates the self-signed cert/key the relay runs with; the relay
//!     itself can generate one, but the client must pin the leaf, so the
//!     files are the source of truth both sides read.
//!
//! rp_dev_setup gen-tenant
//!     Prints two lines: the tenant signing key's PKCS#8 hex (for minting
//!     tokens) and its public key hex (for the relay's --tenant-pubkey).
//!
//! rp_dev_setup setup --tenant-pkcs8 <hex> --kid <kid> --tenant <name> \
//!     --session <n> --slot <n> --relay <ip:port> --server-name <name> \
//!     --cert-file <file.pem> [--client-key-pkcs8 <hex>] --out <setup.json>
//!     Mints the session token for one slot and writes the launch JSON
//!     `rp_start` consumes (a client keypair is generated when none is given).
//! ```

use std::fs;
use std::process::ExitCode;

use base64::prelude::{BASE64_STANDARD, Engine as _};
use rally_point_client::proto::control::TenantId;
use rally_point_client::proto::ids::{SessionId, SlotId};
use rally_point_client::proto::token::{
    ClientPublicKey, ExpiresAt, KeyId, PUBLIC_KEY_LEN, SIGNATURE_LEN, Signature, SignedToken,
    TokenClaims,
};
use rally_point_relay::config::self_signed_cert;
use rally_point_transport::rustls::pki_types::PrivateKeyDer;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::json;

fn keypair() -> Ed25519KeyPair {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("key generation");
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("pkcs8 round-trip")
}

fn pem_of(label: &str, der: &[u8]) -> String {
    let b64 = BASE64_STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn der_from_pem(pem: &str) -> Result<Vec<u8>, String> {
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    let start = pem
        .find(begin)
        .ok_or("cert file holds no certificate")?
        + begin.len();
    let finish = pem[start..].find(end).ok_or("cert file truncated")? + start;
    let b64: String = pem[start..finish].chars().filter(|c| !c.is_whitespace()).collect();
    BASE64_STANDARD.decode(b64).map_err(|e| e.to_string())
}

fn mint_token(
    tenant_pkcs8: &[u8],
    kid: &str,
    tenant: &str,
    session: u64,
    slot: u8,
    client_pub: [u8; PUBLIC_KEY_LEN],
) -> SignedToken {
    let tenant_key = Ed25519KeyPair::from_pkcs8(tenant_pkcs8).expect("tenant key");
    let claims = TokenClaims::new(
        TenantId(tenant.to_string()),
        SessionId(session),
        SlotId(slot),
        ExpiresAt(u64::MAX),
        ClientPublicKey(client_pub),
    );
    let mut token = SignedToken::from_parts(
        KeyId(kid.to_string()),
        claims,
        Signature([0; SIGNATURE_LEN]),
    );
    let mut message = Vec::new();
    token.signed_message(&mut message).expect("signed message");
    token.signature = Signature(tenant_key.sign(&message).as_ref().try_into().unwrap());
    token
}

fn next_arg(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{flag} needs a value"))
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let sub = match args.next() {
        Some(s) => s,
        None => {
            eprintln!("usage: rp_dev_setup <gen-cert|gen-tenant|setup> ...");
            return ExitCode::FAILURE;
        }
    };
    match sub.as_str() {
        "gen-cert" => {
            let mut cert_path = None;
            let mut key_path = None;
            while let Some(a) = args.next() {
                match a.as_str() {
                    "--cert" => cert_path = Some(next_arg(&mut args, "--cert").unwrap()),
                    "--key" => key_path = Some(next_arg(&mut args, "--key").unwrap()),
                    other => {
                        eprintln!("unknown flag {other}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            let (cert_path, key_path) = match (cert_path, key_path) {
                (Some(c), Some(k)) => (c, k),
                _ => {
                    eprintln!("gen-cert needs --cert and --key");
                    return ExitCode::FAILURE;
                }
            };
            let cert = self_signed_cert().expect("self-signed cert");
            let cert_pem = pem_of("CERTIFICATE", cert.chain[0].as_ref());
            let key_pem = match &cert.key {
                PrivateKeyDer::Pkcs8(k) => pem_of("PRIVATE KEY", k.secret_pkcs8_der()),
                other => {
                    eprintln!("unexpected private key kind: {other:?}");
                    return ExitCode::FAILURE;
                }
            };
            fs::write(&cert_path, cert_pem).expect("writing cert");
            fs::write(&key_path, key_pem).expect("writing key");
            println!("wrote {cert_path} and {key_path}");
        }
        "gen-tenant" => {
            let pair = keypair();
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("gen");
            // Re-derive the pkcs8 the pair above was made from so both halves
            // come from one document.
            let _ = &pkcs8;
            let pair2 = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("round-trip");
            let _ = pair;
            println!("{}", hex::encode(pkcs8.as_ref()));
            println!("{}", hex::encode(pair2.public_key().as_ref()));
        }
        "coord-create" => {
            // The coordinated dev flow: ask a dev-tenant coordinator to mint a
            // session on its enrolled relay, then write each slot's launch JSON.
            //
            //   rp_dev_setup coord-create --coordinator http://127.0.0.1:14910 \
            //       --tenant <id> --kid <kid> --client-seed <hex> \
            //       --slots <n> [--server-name localhost] --out-dir <dir>
            let mut coordinator: Option<String> = None;
            let mut tenant = "sb-dev".to_string();
            let mut kid = "dev-key-1".to_string();
            let mut client_seed: Option<String> = None;
            let mut slots: u32 = 2;
            let mut server_name = "localhost".to_string();
            let mut out_dir: Option<String> = None;
            let mut game_name = "Relay".to_string();
            while let Some(a) = args.next() {
                match a.as_str() {
                    "--coordinator" => {
                        coordinator = Some(next_arg(&mut args, "--coordinator").unwrap())
                    }
                    "--tenant" => tenant = next_arg(&mut args, "--tenant").unwrap(),
                    "--kid" => kid = next_arg(&mut args, "--kid").unwrap(),
                    "--client-seed" => {
                        client_seed = Some(next_arg(&mut args, "--client-seed").unwrap())
                    }
                    "--slots" => slots = next_arg(&mut args, "--slots").unwrap().parse().unwrap(),
                    "--server-name" => {
                        server_name = next_arg(&mut args, "--server-name").unwrap()
                    }
                    "--name" => game_name = next_arg(&mut args, "--name").unwrap(),
                    "--out-dir" => out_dir = Some(next_arg(&mut args, "--out-dir").unwrap()),
                    other => {
                        eprintln!("unknown flag {other}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            let (coordinator, out_dir) = match (coordinator, out_dir) {
                (Some(c), Some(o)) => (c, o),
                _ => {
                    eprintln!("coord-create needs --coordinator and --out-dir");
                    return ExitCode::FAILURE;
                }
            };
            std::fs::create_dir_all(&out_dir).expect("out dir");

            // The tenant's app-server signing key: a raw 32-byte Ed25519 seed
            // (the coordinator's --dev-tenant-client-key).
            let seed = match &client_seed {
                Some(h) => {
                    let bytes = hex::decode(h).expect("client seed hex");
                    let seed: [u8; 32] = bytes.try_into().expect("seed length");
                    seed
                }
                None => {
                    let mut seed = [0u8; 32];
                    use ring::rand::SecureRandom;
                    ring::rand::SystemRandom::new().fill(&mut seed).expect("rng");
                    eprintln!("generated a client seed; pin it with --client-seed {}",
                              hex::encode(seed));
                    seed
                }
            };
            let client_key = Ed25519KeyPair::from_seed_unchecked(&seed).expect("client key");

            // One ephemeral per-slot keypair (kept as its PKCS#8 document, which
            // the client handoff carries), whose public half rides the token.
            let slot_docs: Vec<Vec<u8>> = (0..slots)
                .map(|_| {
                    Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                        .expect("keygen")
                        .as_ref()
                        .to_vec()
                })
                .collect();
            let slot_keys: Vec<Ed25519KeyPair> = slot_docs
                .iter()
                .map(|d| Ed25519KeyPair::from_pkcs8(d).expect("pkcs8 round trip"))
                .collect();
            let players = slot_keys
                .iter()
                .enumerate()
                .map(|(i, k)| {
                    let pubkey: [u8; PUBLIC_KEY_LEN] =
                        k.public_key().as_ref().try_into().unwrap();
                    rally_point_client::proto::control::PlayerHandoff {
                        require_evidence: false,
                        slot: SlotId(i as u8),
                        client_pubkey: ClientPublicKey(pubkey),
                        external_ref: None,
                        observer: false,
                        region: None,
                    }
                })
                .collect::<Vec<_>>();
            let request = rally_point_client::proto::control::SessionRequest {
                periodic_evidence: false,
                evidence_keys: vec![],
                tenant: TenantId(tenant.clone()),
                players,
                external_id: Some(format!("dev-{}", std::process::id())),
                latency_estimate_ms: None,
                rollback: false,
                lobby_policy: None,
            };
            let body = serde_json::to_vec(&request).expect("request json");
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_secs()
                .to_string();
            let message = rally_point_client::proto::request_auth::request_message(
                &ts, "POST", "/session/create", &body,
            );
            let signature = client_key.sign(&message);
            let sig_hex = hex::encode(signature.as_ref());

            // Plain HTTP for the dev coordinator.
            let url = format!("{coordinator}/session/create");
            let mut stream = std::net::TcpStream::connect(
                url.strip_prefix("http://").expect("http coordinator url")
                    .split('/')
                    .next()
                    .expect("host:port"),
            )
            .expect("coordinator connection");
            use std::io::Write;
            write!(
                stream,
                "POST /session/create HTTP/1.1\r\nHost: dev\r\nContent-Type: application/json\r\nContent-Length: {}\r\nx-rp2-timestamp: {}\r\nx-rp2-signature: {}\r\nConnection: close\r\n\r\n",
                body.len(),
                ts,
                sig_hex
            )
            .expect("request");
            stream.write_all(&body).expect("request body");
            use std::io::Read;
            let mut raw = Vec::new();
            stream.read_to_end(&mut raw).expect("response");
            let text = String::from_utf8_lossy(&raw);
            let json = text
                .split("\r\n\r\n")
                .nth(1)
                .expect("http response body");
            let response: rally_point_client::proto::control::SessionResponse =
                serde_json::from_str(json).expect("session response");

            let addrs: Vec<String> = std::iter::once(response.home_relay.relay_addr.to_string())
                .chain(response.home_relay.relay_addrs.iter().map(|a| a.to_string()))
                .collect();
            let cert_b64 = BASE64_STANDARD.encode(&response.home_relay.cert_der);
            let mut outs = Vec::new();
            for (i, token) in response.tokens.iter().enumerate() {
                let setup = json!({
                    "token": BASE64_STANDARD.encode(&token.token),
                    "clientPrivateKey": BASE64_STANDARD.encode(&slot_docs[i]),
                    "homeRelay": {
                        "relayId": response.home_relay.relay_id.0,
                        "addrs": addrs,
                        "serverName": server_name,
                        "cert": cert_b64,
                    },
                    "initialBufferTurns": response.bounds.min,
                    "rosterSize": slots,
                    "gameName": game_name,
                });
                let path = format!("{out_dir}/s{i}.json");
                std::fs::write(&path, serde_json::to_string_pretty(&setup).unwrap())
                    .expect("writing setup");
                outs.push(path);
            }
            println!("coordinator minted session {}; wrote {}", response.session.0, outs.join(", "));
        }
        "setup" => {            let mut tenant_pkcs8: Option<String> = None;
            let mut kid = "dev-key-1".to_string();
            let mut tenant = "hyperion-dev".to_string();
            let mut session: u64 = 1;
            let mut slot: u8 = 0;
            let mut relay: Option<String> = None;
            let mut server_name = "localhost".to_string();
            let mut cert_file: Option<String> = None;
            let mut client_key: Option<String> = None;
            let mut out_path: Option<String> = None;
            let mut players: u32 = 0;
            let mut game_name = "Relay".to_string();
            while let Some(a) = args.next() {
                match a.as_str() {
                    "--tenant-pkcs8" => {
                        tenant_pkcs8 = Some(next_arg(&mut args, "--tenant-pkcs8").unwrap())
                    }
                    "--kid" => kid = next_arg(&mut args, "--kid").unwrap(),
                    "--tenant" => tenant = next_arg(&mut args, "--tenant").unwrap(),
                    "--session" => {
                        session = next_arg(&mut args, "--session").unwrap().parse().unwrap()
                    }
                    "--slot" => slot = next_arg(&mut args, "--slot").unwrap().parse().unwrap(),
                    "--relay" => relay = Some(next_arg(&mut args, "--relay").unwrap()),
                    "--server-name" => {
                        server_name = next_arg(&mut args, "--server-name").unwrap()
                    }
                    "--cert-file" => cert_file = Some(next_arg(&mut args, "--cert-file").unwrap()),
                    "--client-key-pkcs8" => {
                        client_key = Some(next_arg(&mut args, "--client-key-pkcs8").unwrap())
                    }
                    "--players" => players = next_arg(&mut args, "--players").unwrap().parse().unwrap(),
                    "--name" => game_name = next_arg(&mut args, "--name").unwrap(),
                    "--out" => out_path = Some(next_arg(&mut args, "--out").unwrap()),
                    other => {
                        eprintln!("unknown flag {other}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            let tenant_pkcs8 = match tenant_pkcs8 {
                Some(h) => hex::decode(h).expect("tenant pkcs8 hex"),
                None => {
                    eprintln!("setup needs --tenant-pkcs8");
                    return ExitCode::FAILURE;
                }
            };
            let (relay, cert_file, out_path) = match (relay, cert_file, out_path) {
                (Some(r), Some(c), Some(o)) => (r, c, o),
                _ => {
                    eprintln!("setup needs --relay, --cert-file and --out");
                    return ExitCode::FAILURE;
                }
            };

            // The client's per-session keypair.
            let client_pkcs8 = match &client_key {
                Some(h) => hex::decode(h).expect("client pkcs8 hex"),
                None => {
                    let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("gen");
                    doc.as_ref().to_vec()
                }
            };
            let client_pair = Ed25519KeyPair::from_pkcs8(&client_pkcs8).expect("client key");
            let client_pub: [u8; PUBLIC_KEY_LEN] =
                client_pair.public_key().as_ref().try_into().unwrap();

            let token = mint_token(&tenant_pkcs8, &kid, &tenant, session, slot, client_pub);
            let token_b64 = BASE64_STANDARD.encode(token.encode().expect("token encode"));

            let cert_pem = fs::read_to_string(&cert_file).expect("cert file");
            let cert_b64 = BASE64_STANDARD.encode(der_from_pem(&cert_pem).expect("cert der"));

            let setup = json!({
                "token": token_b64,
                "clientPrivateKey": BASE64_STANDARD.encode(&client_pkcs8),
                "homeRelay": {
                    "relayId": 1,
                    "addrs": [relay],
                    "serverName": server_name,
                    "cert": cert_b64,
                },
                "initialBufferTurns": 2,
                "rosterSize": players,
                "gameName": game_name,
            });
            fs::write(&out_path, serde_json::to_string_pretty(&setup).unwrap())
                .expect("writing setup");
            println!("wrote {out_path} (session {session}, slot {slot})");
        }
        other => {
            eprintln!("unknown subcommand {other}");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}
