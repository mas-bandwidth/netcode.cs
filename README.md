# netcode.cs

[![CI](https://github.com/mas-bandwidth/netcode.cs/actions/workflows/ci.yml/badge.svg)](https://github.com/mas-bandwidth/netcode.cs/actions/workflows/ci.yml)

If this library helps you, please support it: **[Become a supporter](https://www.patreon.com/MasBandwidth/membership)**

**Status: released** — v1.0.0, the first release. Wire compatibility with the C reference is proven in CI on every push (the "C wire compatibility" gate).

C# port of [netcode](https://github.com/mas-bandwidth/netcode), a simple protocol
for creating secure client/server connections over UDP (protocol
"NETCODE 1.02"). The wire is byte-identical to the C reference implementation:
connect tokens minted by either implementation are accepted by the other,
encrypted packets cross-decrypt, and a C client connects to a C# server (and
vice versa) exactly as it would to the C one. Wire compatibility is proven, not
asserted: the interop gate builds the real `netcode.c`, requires byte-identical
token and packet goldens in both directions, and runs live cross-implementation
client/server sessions over localhost UDP.

Family values: zero third-party dependencies (including test frameworks and the
crypto — see below); hostile packet data never throws — malformed input is
ignored, exactly as the C library ignores it (exceptions are reserved for API
misuse); no unsafe code; zero allocation on the steady-state packet paths,
asserted by a test.

## License

AGPL-3.0 for now; intended to move to MBSL when ready.

## What this is

netcode solves connection-oriented, encrypted, authenticated UDP for games:

1. A backend authenticates a client and mints it a _connect token_ over HTTPS.
2. The client presents the token to a dedicated server over UDP.
3. The server validates the token (encrypted with a private key shared between
   backend and servers), challenges the client to prove its address, assigns it
   a slot, and from then on every packet is encrypted and authenticated with
   per-session keys carried inside the token.

The API is idiomatic C# over the same non-blocking update-loop model as the C
library — games call `Update(time)` every frame; nothing spawns threads or
tasks; `Span<byte>` in and out of the payload paths:

```csharp
// server
var config = new ServerConfig { ProtocolId = protocolId, PrivateKey = privateKey };
using var server = new Server("10.0.0.1:40000", config);
server.Start(maxClients: 64);
// every frame:
server.Update(time);
while ((bytes = server.ReceivePacket(clientIndex, buffer, out var sequence)) >= 0) { ... }
server.SendPacket(clientIndex, payload);

// client
using var client = new Client("0.0.0.0:0");
client.Connect(connectToken);          // 2048 bytes from your backend
// every frame:
client.Update(time);
if (client.State == ClientState.Connected) client.SendPacket(payload);
while ((bytes = client.ReceivePacket(buffer, out var sequence)) >= 0) { ... }

// backend
ConnectTokenGenerator.Generate(publicAddresses, internalAddresses,
    expireSeconds: 30, timeoutSeconds: 15, clientId, protocolId, privateKey,
    userData, tokenBuffer);
```

Set `ServerConfig.MaxConnectTokenLifetime` to the longest lifetime issued by
the backend (the default is 30 seconds); the server rejects tokens that could
have been issued before its current start.

Like the C library, client and server objects are single-threaded by design and
perform no internal synchronization.

## Layout

- `src/Netcode.cs` — protocol core: addresses, connect/challenge tokens, packet
  read/write, replay protection, encryption manager, packet queues, the
  deterministic network simulator.
- `src/Client.cs`, `src/Server.cs` — the endpoint state machines, ported
  line-for-line from `netcode.c`.
- `src/Crypto.cs` — the two AEAD constructions, fully managed (see below).
- `tests/` — console test runner, no test framework: exit code is the verdict.
  A test-for-test port of the C suite, plus seeded hostile fuzz over every parse
  path, a zero-allocation assertion, and a managed-vs-BCL crypto differential.
  `dotnet run --project tests/Tests.csproj -- soak 5000` runs the bounded soak.
- `compat/` — the cross-implementation interop harness: `Compat.csproj` (C#
  half) and `c/compat.c` (C half, built against the real `netcode.c` + its
  vendored libsodium).
- `scripts/interop.sh` — the interop gate as one runnable command.
- `STANDARD.md` — the protocol standard, vendored verbatim from the C repo
  (CI diffs it against upstream and fails on drift).
- `notes/` — the port map and design records.

## Build and test

```sh
dotnet build src/Netcode.csproj                       # builds net8.0 + net10.0
dotnet run --project tests/Tests.csproj -f net10.0    # the whole suite
dotnet run --project tests/Tests.csproj -f net8.0     # the LTS leg (needs the .NET 8
                                                      # runtime, or DOTNET_ROLL_FORWARD=LatestMajor)
dotnet run --project tests/Tests.csproj -f net10.0 -- address   # only tests matching a substring
scripts/interop.sh ../netcode                         # the interop gate (needs a netcode clone + a C compiler)
```

## The crypto

netcode uses exactly two libsodium constructions on the wire:
**XChaCha20-Poly1305** (`crypto_aead_xchacha20poly1305_ietf`) for the private
connect token, and **ChaCha20-Poly1305 IETF** (RFC 8439) for challenge tokens
and encrypted packets.

This port implements both in fully managed C# (`src/Crypto.cs`) — ChaCha20,
Poly1305 (44-bit limbs over `UInt128`), HChaCha20 — as a single production code
path with no platform primitives and no P/Invoke, so behavior is identical on
every OS and TFM and the zero-dependency family value holds. .NET's built-in
`ChaCha20Poly1305` was rejected as the production path because it is
platform-gated (`IsSupported` varies by OS) and has no XChaCha20 variant; it is
instead used by the test suite as an independent differential oracle wherever
the platform provides it. libsodium P/Invoke was rejected as a native
deployment burden and a violation of the zero-dependency rule.

The construction is pinned four ways: known-answer tests carrying the same
golden bytes as `netcode.c`'s `test_crypto_aead_vectors` (generated from
libsodium reference output), tamper-rejection tests, the BCL differential, and
the interop gate against libsodium itself. Constant-time discipline: ChaCha20
and Poly1305 are add-rotate-xor / integer-multiply with no secret-dependent
branches or lookups; the tag comparison is
`CryptographicOperations.FixedTimeEquals`; on decrypt, plaintext is only
produced after the tag verifies.

## Deliberate design decisions (do not "fix")

Inherited from the C reference implementation, on purpose:

- **Flat arrays and linear scans** for client lookup and the encryption mapping
  search. An attacker controls the keys (source addresses) and could drive a
  hash table into its worst case; linear is the hardened choice at netcode's
  scale (~100 players).
- **Connect-token single-use tracking is constant-time worst-case**: the
  find-or-add scan always walks every entry, so timing does not leak whether a
  token was seen. Pending entries admit only same-address retransmits;
  installation consumes the token for every address, and unexpired entries are
  never evicted.
- **Per-packet socket send errors are swallowed.** UDP is unreliable; a send
  error is semantically identical to a dropped packet, and a persistently dead
  socket surfaces as a connection timeout through the state machine.
- **The server has no state machine of its own** beyond stopped/started; all
  other state is per-client.
- **The server's global packet sequence is re-seeded to 2^63 on every start.**
  Global packets (challenge/denied) share per-token keys with per-client
  packets whose sequences start at zero; the split sequence space keeps AEAD
  nonces disjoint. Regression-tested.
- **Replay protection advances its window only after AEAD authentication.**
  The pre-decrypt check is an optimization; advancing before authentication
  would let spoofed sequence numbers poison the window.

Differences from the C library, also on purpose:

- Creation failures throw `NetcodeException` (carrying the same error codes)
  instead of returning NULL — exceptions are for API misuse and environment
  failure, never for wire data.
- Received payloads are copied out of pooled ring buffers
  (`ReceivePacket(Span<byte>, out ulong)`) instead of returning allocated
  packets to free — that is what makes the steady state allocation-free.
- `netcode_init/term` have no equivalent (nothing to initialize in .NET).
- Windows packet tagging (Qwave) is not ported; `EnablePacketTagging` is
  best-effort DSCP on unix/macOS and a no-op on Windows.

## Security

Never embed a production private key in a client. The fixed key in the test
suite and interop harness is the C repo's published test key — test-only and
obviously non-production. Report vulnerabilities privately (see the C repo's
SECURITY.md for the family process).
