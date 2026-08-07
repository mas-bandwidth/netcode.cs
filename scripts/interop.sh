#!/bin/sh
# The cross-implementation interop gate, runnable as one command. Exit code is the verdict.
#
#   scripts/interop.sh [path-to-netcode-clone]
#
# Builds the C half of the compat harness against the REAL netcode.c (plus its
# vendored libsodium), then runs four legs:
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
NETCODE="${1:-../netcode}"
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
"$CC" -O2 -Wall -I "$NETCODE" -I "$NETCODE/sodium" -o "$WORK/compat-c" compat/c/compat.c "$NETCODE/sodium/sodium.c" -lm

echo "== building C# compat harness"
dotnet build compat/Compat.csproj -c Release --nologo -v quiet
CS="dotnet run -c Release --project compat/Compat.csproj --no-build --"

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

echo "== leg 3: live session, C server <- C# client (token minted by C#)"
$CS mint "$WORK/token-a.bin" 127.0.0.1:40765
"$WORK/compat-c" server 40765 &
SERVER_PID=$!
sleep 1
$CS client 40765 "$WORK/token-a.bin"
wait "$SERVER_PID"
SERVER_PID=""

echo "== leg 4: live session, C# server <- C client (token minted by C)"
"$WORK/compat-c" mint "$WORK/token-b.bin" 127.0.0.1:40766
$CS server 40766 &
SERVER_PID=$!
sleep 2
"$WORK/compat-c" client 40766 "$WORK/token-b.bin"
wait "$SERVER_PID"
SERVER_PID=""

echo "INTEROP GATE PASSED"
