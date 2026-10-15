#!/bin/sh
# The cross-implementation interop gate, runnable as one command. Exit code is the verdict.
#
#   scripts/interop.sh [path-to-netcode-clone]
#
# Builds the C half of the compat harness against the REAL netcode.c (plus its
# vendored libsodium), then runs ten legs:
#
#   1. golden byte identity — both sides write the same token/packet goldens from
#      the same fixed keys/nonces/timestamps; every file must be byte identical.
#   2. cross verify — each side decrypts and parses the other side's goldens
#      through its real read paths.
#   3. live session A — C server, C# client, connect token minted by C#:
#      connect, exchange payloads both ways, clean client-side disconnect.
#   4. live session B — C# server, C client, connect token minted by C.
#
# CI pins the netcode clone to a fixed ref; locally the clone may track HEAD.

set -e

cd "$(dirname "$0")/.."

CC="${CC:-cc}"
NETCODE="${1:-}"

if [ -z "$NETCODE" ] || [ ! -f "$NETCODE/netcode.c" ]; then
    echo "INTEROP SKIPPED: no mas-bandwidth/netcode clone reachable."
    echo "Run: scripts/interop.sh <path-to-netcode-clone>"
    echo "The default ../netcode was checked and is not present."
    exit 0
fi

if ! git -C "$NETCODE" merge-base --is-ancestor 5cc4798d HEAD; then
    echo "INTEROP FAILED: C reference must contain challenge MAC binding (5cc4798d)."
    exit 1
fi

if ! git -C "$NETCODE" merge-base --is-ancestor 1c58478d HEAD; then
    echo "INTEROP FAILED: C reference must contain random global sequence and reused-token refusal (1c58478d)."
    exit 1
fi

if ! git -C "$NETCODE" merge-base --is-ancestor 067b1959 HEAD ||
   ! git -C "$NETCODE" merge-base --is-ancestor 39f04965 HEAD; then
    echo "INTEROP FAILED: C reference must contain both token-lifetime and socket-family fixes."
    exit 1
fi

WORK="$(mktemp -d)"
SERVER_PID=""

cleanup()
{
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "== building C compat harness against $NETCODE"
"$CC" -O2 -ffp-contract=off -Wall -I "$NETCODE" -I "$NETCODE/sodium" -o "$WORK/compat-c" compat/c/compat.c "$NETCODE/sodium/sodium.c" -lm

echo "== building C# compat harness"
mkdir "$WORK/nuget-empty"
dotnet restore compat/Compat.csproj --source "$WORK/nuget-empty" --ignore-failed-sources -p:UseAppHost=false --nologo -v quiet
dotnet build compat/Compat.csproj -c Release --no-restore -p:UseAppHost=false --nologo -v quiet
CS="dotnet compat/bin/Release/net10.0/Compat.dll"

echo "== leg 1: golden byte identity (both sides write, every file must match)"
mkdir "$WORK/c-goldens" "$WORK/cs-goldens"
"$WORK/compat-c" goldens "$WORK/c-goldens"
$CS goldens "$WORK/cs-goldens"
for f in private_token.bin public_token.bin challenge_token.bin \
         packet_request.bin packet_denied.bin packet_challenge.bin packet_response.bin \
         packet_keepalive.bin packet_payload.bin packet_disconnect.bin; do
    cmp "$WORK/c-goldens/$f" "$WORK/cs-goldens/$f"
    echo "   identical: $f"
done

echo "== leg 2: cross verify (each side reads the other's goldens)"
"$WORK/compat-c" verify "$WORK/cs-goldens"
$CS verify "$WORK/c-goldens"

echo "== leg 3: mapping-bound challenge differential (fixed tokens, explicit timestamp, override transport)"
mkdir "$WORK/c-inputs" "$WORK/cs-inputs"
$CS challenge-mapping "$WORK/cs-inputs" > "$WORK/cs-challenge.txt"
"$WORK/compat-c" challenge-mapping "$WORK/c-inputs" > "$WORK/c-challenge.txt"
for f in token-a.bin token-b.bin token-c.bin; do
    cmp "$WORK/c-inputs/$f" "$WORK/cs-inputs/$f"
    echo "   identical input: $f"
done
if ! diff -u "$WORK/c-challenge.txt" "$WORK/cs-challenge.txt"; then
    echo "   mapping-bound challenge differential differed; first differing lines above"
    exit 1
fi
echo "   mapping-bound challenge differential matched"
for f in challenge-A.bin challenge-B.bin challenge-C1.bin challenge-C2.bin \
         01-request-A.bin 02-request-B.bin 03-response-Y-A.bin 04-response-Y-B.bin \
         05-request-C1.bin 06-request-C2.bin 07-response-X-A.bin 08-response-X-C1.bin; do
    cmp "$WORK/c-inputs/$f" "$WORK/cs-inputs/$f"
    echo "   identical input: $f"
done

echo "== leg 4: live session, C server <- C# client (token minted by C#)"
"$WORK/compat-c" server 40765 &
SERVER_PID=$!
sleep 1
$CS mint "$WORK/token-a.bin" 127.0.0.1:40765
$CS client 40765 "$WORK/token-a.bin"
wait "$SERVER_PID"
SERVER_PID=""

echo "== leg 5: live session, C# server <- C client (token minted by C)"
$CS server 40766 &
SERVER_PID=$!
sleep 2
"$WORK/compat-c" mint "$WORK/token-b.bin" 127.0.0.1:40766
"$WORK/compat-c" client 40766 "$WORK/token-b.bin"
wait "$SERVER_PID"
SERVER_PID=""

echo "== leg 6: packet-reader differential (hostile/golden vectors through both readers)"
$CS diffpackets > "$WORK/cs-diff.txt"
"$WORK/compat-c" diffpackets > "$WORK/c-diff.txt"
diff -u "$WORK/c-diff.txt" "$WORK/cs-diff.txt"
echo "   packet-reader differential matched"

echo "== leg 7: receive-drain differential (scripted override queues through both drains)"
$CS drain > "$WORK/cs-drain.txt"
"$WORK/compat-c" drain > "$WORK/c-drain.txt"
diff -u "$WORK/c-drain.txt" "$WORK/cs-drain.txt"
echo "   receive-drain differential matched"

echo "== leg 8: global nonce differential (override transport, boolean properties only)"
$CS nonces > "$WORK/cs-nonces.txt"
"$WORK/compat-c" nonces > "$WORK/c-nonces.txt"
if ! diff -u "$WORK/c-nonces.txt" "$WORK/cs-nonces.txt"; then
    echo "   global nonce differential differed; first differing lines above"
    exit 1
fi
echo "   global nonce differential matched"

echo "== leg 9: token-lifetimes differential (preconnect mapping lifetime)"
$CS token-lifetimes > "$WORK/cs-lifetimes.txt"
"$WORK/compat-c" token-lifetimes > "$WORK/c-lifetimes.txt"
if ! diff -u "$WORK/c-lifetimes.txt" "$WORK/cs-lifetimes.txt"; then
    echo "   token-lifetimes differential differed; first differing lines above"
    exit 1
fi
echo "   token-lifetimes differential matched"

echo "== leg 10: client-address differential (socket-family refusal)"
$CS client-address > "$WORK/cs-client-address.txt"
"$WORK/compat-c" client-address > "$WORK/c-client-address.txt"
if ! diff -u "$WORK/c-client-address.txt" "$WORK/cs-client-address.txt"; then
    echo "   client-address differential differed; first differing lines above"
    exit 1
fi
echo "   client-address differential matched"

echo "== leg 11: disconnect callback reentry differential (fixed packets, override transport)"
mkdir "$WORK/c-reentry" "$WORK/cs-reentry"
$CS disconnect-reentry "$WORK/cs-reentry" > "$WORK/cs-reentry.txt"
"$WORK/compat-c" disconnect-reentry "$WORK/c-reentry" > "$WORK/c-reentry.txt"
for case_name in same stop timeout; do
    cmp "$WORK/c-reentry/$case_name-request.bin" "$WORK/cs-reentry/$case_name-request.bin"
    cmp "$WORK/c-reentry/$case_name-response.bin" "$WORK/cs-reentry/$case_name-response.bin"
done
if ! diff -u "$WORK/c-reentry.txt" "$WORK/cs-reentry.txt"; then
    echo "   disconnect callback reentry differential differed; first differing lines above"
    exit 1
fi
echo "   disconnect callback reentry differential matched"

echo "INTEROP GATE PASSED"
