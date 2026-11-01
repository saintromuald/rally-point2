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
        "setup" => {
            let mut tenant_pkcs8: Option<String> = None;
            let mut kid = "dev-key-1".to_string();
            let mut tenant = "hyperion-dev".to_string();
            let mut session: u64 = 1;
            let mut slot: u8 = 0;
            let mut relay: Option<String> = None;
            let mut server_name = "localhost".to_string();
            let mut cert_file: Option<String> = None;
            let mut client_key: Option<String> = None;
            let mut out_path: Option<String> = None;
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
