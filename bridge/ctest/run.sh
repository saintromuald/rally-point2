#!/usr/bin/env bash
# Phase 1 gate: two C clients finish a lockstep exchange through a standalone
# rally-point relay on one machine.
#
#   bridge/ctest/run.sh [turns]
#
set -euo pipefail
cd "$(dirname "$0")/.."          # bridge/

TURNS="${1:-50}"
ROOT="$(pwd)/.."                 # the rally-point2 workspace root
WORK="$(mktemp -d)"
trap 'kill ${RELAY_PID:-} 2>/dev/null || true' EXIT

echo "[run] building"
cargo build -q -p rally-point-relay --bin rally-point-relay
cargo build -q -p rp-dev-setup
cargo build -q -p rally-point-bridge --lib

BIN="$ROOT/target/debug"

echo "[run] generating relay cert and tenant key"
"$BIN/rp_dev_setup" gen-cert --cert "$WORK/cert.pem" --key "$WORK/key.pem"
"$BIN/rp_dev_setup" gen-tenant > "$WORK/tenant.txt"
TENANT_PKCS8="$(sed -n '1p' "$WORK/tenant.txt")"
TENANT_PUB="$(sed -n '2p' "$WORK/tenant.txt")"

PORT=$((15000 + RANDOM % 1000))
echo "[run] starting relay on 127.0.0.1:$PORT"
"$BIN/rally-point-relay" \
    --listen "127.0.0.1:$PORT" \
    --cert "$WORK/cert.pem" --key "$WORK/key.pem" \
    --tenant-pubkey "$TENANT_PUB" --kid dev-key-1 --tenant hyperion-dev \
    > "$WORK/relay.log" 2>&1 &
RELAY_PID=$!
sleep 1

echo "[run] minting setups for slot 0 and slot 1"
"$BIN/rp_dev_setup" setup \
    --tenant-pkcs8 "$TENANT_PKCS8" --kid dev-key-1 --tenant hyperion-dev \
    --session 1 --slot 0 --relay "127.0.0.1:$PORT" --server-name localhost \
    --cert-file "$WORK/cert.pem" --out "$WORK/s0.json"
"$BIN/rp_dev_setup" setup \
    --tenant-pkcs8 "$TENANT_PKCS8" --kid dev-key-1 --tenant hyperion-dev \
    --session 1 --slot 1 --relay "127.0.0.1:$PORT" --server-name localhost \
    --cert-file "$WORK/cert.pem" --out "$WORK/s1.json"

echo "[run] building ctest against the staticlib"
cc -O1 -o "$WORK/ctest" ctest/ctest.c \
    "$BIN/librally_point_bridge.a" -lpthread -ldl -lm

echo "[run] two clients exchanging $TURNS turns"
"$WORK/ctest" "$WORK/s0.json" "$TURNS" > "$WORK/c0.log" 2>&1 &
C0=$!
"$WORK/ctest" "$WORK/s1.json" "$TURNS" > "$WORK/c1.log" 2>&1 &
C1=$!
set +e
wait "$C0"; R0=$?
wait "$C1"; R1=$?
set -e

echo "---- slot 0 ----"; tail -8 "$WORK/c0.log"
echo "---- slot 1 ----"; tail -8 "$WORK/c1.log"

if [ "$R0" -eq 0 ] && [ "$R1" -eq 0 ]; then
    echo "[run] PASS: both clients received all $TURNS turns"
else
    echo "[run] FAIL (slot0=$R0 slot1=$R1); relay log:" >&2
    tail -30 "$WORK/relay.log" >&2
    exit 1
fi
