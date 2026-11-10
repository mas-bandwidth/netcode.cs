# netcode.cs port map

C# port of [mas-bandwidth/netcode](https://github.com/mas-bandwidth/netcode)
(C reference, version 1.4.8, protocol "NETCODE 1.02"). The WIRE is the C
library's, byte-exact; the API is idiomatic C#, mirroring the C library's
non-blocking update-loop model (games call `Update()` each frame — no async
redesign).

## Protocol objects → C# shapes

| C | C# | Notes |
|---|---|-------|
| `netcode_address_t` | `struct Address` | value type, 19 bytes of state: type (None/IPv4/IPv6), port, 16-byte inline data. `Parse`/`TryParse`/`ToString` reproduce the C parser's observable behavior (strict dotted-quad IPv4, port suffix rules, the deliberately lenient `[::1`). |
| `netcode_connect_token_private_t` | `sealed class ConnectTokenPrivate` (internal) | read/write to the fixed 1024-byte buffer |
| `netcode_connect_token_t` (public 2048) | `sealed class ConnectTokenData` (internal parse) + `public static class ConnectTokenGenerator` | `Generate(...)` is the public mint API, signature mirrors `netcode_generate_connect_token` |
| `netcode_challenge_token_t` | `sealed class ChallengeToken` (internal) | 300-byte buffer, 8+256 payload |
| packet structs (7 types) | internal static `PacketIO.WriteConnectionRequestPacket` / `WriteEncryptedPacket` / `ReadPacket` over `Span<byte>` | no per-packet allocation: `ReadPacket` decrypts in place and returns a `ReadPacketResult` (type, sequence, offset and length of the decrypted data in the caller's buffer) |
| `netcode_replay_protection_t` | `sealed class ReplayProtection` (internal) | 256-entry window, identical overflow-safe compare |
| `netcode_packet_queue_t` | `sealed class PacketQueue` (internal) | ring of 256; each slot owns a `MaxPayloadBytes` buffer allocated on first use and reused after that |
| `netcode_encryption_manager_t` | `sealed class EncryptionManager` (internal) | flat arrays + linear scan, same as C — deliberate (attacker controls addresses; linear is the hardened choice, per upstream) |
| `netcode_connect_token_entry_t[]` | `sealed class ConnectTokenHistory` (internal, `src/Server.cs`) | constant-time worst-case scan; free/pending/consumed state, expiry timestamps; the history index is carried by the encryption mapping |
| `netcode_network_simulator_t` | `public sealed class NetworkSimulator` | same xorshift64* RNG, same seed, so loss/jitter sequences match the C library run-for-run; each ring slot copies its packet into a `MaxPacketBytes` buffer allocated when the slot is empty (see the class comment) |
| `netcode_client_t` | `public sealed class Client` | states as `public enum ClientState` (same numeric values −6..3) |
| `netcode_server_t` | `public sealed class Server` | flat per-client arrays, max 256 clients, global sequence seeded `1UL<<63` on start AND stop→start (nonce-space separation — upstream 1.4.0 fix, every seeding site kept) |
| `netcode_init/term` | not needed | no WSAStartup / sodium_init equivalent in .NET; documented |
| `netcode_client_create_dual` | `Client` ctor with optional second address | same for `Server` |
| loopback APIs | ported | yojimbo parity |
| packet tagging | `ClientConfig.EnablePacketTagging` / `ServerConfig.EnablePacketTagging`, best-effort | IPv4 TOS + IPv6 TCLASS on unix/mac; Windows Qwave NOT ported (documented) |

## Crypto construction inventory (exact)

Confirmed from `netcode.c` (netcode_encrypt_aead*/netcode_decrypt_aead*) and
`sodium/NOTES.md` — the C library uses exactly two libsodium constructions:

1. `crypto_aead_xchacha20poly1305_ietf_{encrypt,decrypt}` — **private connect
   token only**. 24-byte random nonce, AD = version info (13) ‖ protocol id
   (u64 LE) ‖ expire timestamp (u64 LE). Encrypts bytes [0,1008), MAC in
   [1008,1024).
2. `crypto_aead_chacha20poly1305_ietf_{encrypt,decrypt}` (RFC 8439) —
   **challenge tokens** (no AD, nonce = 4 zero bytes ‖ sequence u64 LE, key =
   random per server start, sequence starts 0) and **encrypted packets**
   (AD = version info ‖ protocol id ‖ prefix byte, nonce = 4 zero bytes ‖
   packet sequence u64 LE).

Plus `randombytes_buf` (keys, token nonces) and `crypto_verify_*`
(constant-time comparison; in netcode used inside the AEAD tag check).

No X25519, no crypto_box, no signatures — nothing else.

## Crypto decision

**Fully managed implementation, single production path** — `src/Crypto.cs`:
ChaCha20 block/stream (RFC 8439), Poly1305 (donna-style 44-bit limbs, `UInt128` products),
HChaCha20, composed into the two AEADs. XChaCha20-Poly1305 =
HChaCha20(key, nonce[0..16)) → subkey, then IETF construction with nonce
`0x00000000 ‖ nonce[16..24)` — exactly libsodium's construction.

Constant-time discipline (red team: this is target #1):
- ChaCha20/Poly1305 have no secret-dependent branches or table lookups by
  construction (add-rotate-xor / integer mul only).
- Tag comparison is `CryptographicOperations.FixedTimeEquals`.
- Decrypt-in-place only writes plaintext after the tag verifies (mirrors
  libsodium 1.0.22's verify-before-stream-xor ordering).
- Key material is not copied beyond what the API requires; transient state is
  zeroed where practical (`CryptographicOperations.ZeroMemory`), though .NET
  GC copying means secret hygiene is best-effort — flagged for red team.

Verification: RFC 8439 KATs (ChaCha20 block, Poly1305, AEAD), the
draft-irtf-cfrg-xchacha KAT + the exact golden vectors from
`test_crypto_aead_vectors()` in netcode.c, tamper-rejection, and a
differential test against `System.Security.Cryptography.ChaCha20Poly1305`
whenever `IsSupported` (macOS/.NET10 and Linux CI both exercise it).
Poly1305 is also checked directly by `test_crypto_poly1305_vectors`
(RFC 8439 Section 2.5.2 and all eleven Appendix A.3 vectors, including the
limb-carry and 2^130 - 5 final-reduction cases) through `Aead.Poly1305Mac`.

Alternatives considered:
- **.NET `ChaCha20Poly1305` as the production IETF path** (+ managed HChaCha20
  for X): construction matches RFC 8439 exactly, hardware-backed, but
  platform-gated (`IsSupported` varies by OS/OpenSSL), which forks the
  production code path per platform and leaves the managed fallback the less
  exercised one. Rejected for a protocol library whose primary value is
  identical behavior everywhere; retained as a *test-time differential oracle*.
- **libsodium P/Invoke**: exact-by-definition, but native deployment burden on
  every TFM/platform, violates the family value of zero third-party
  dependencies, least native-feeling. Rejected.

Performance note: scalar managed ChaCha20 comfortably exceeds the domain's
needs (≤1300-byte packets at game rates; 256 clients × 60 Hz × 1.2 KB ≈
18 MB/s, measured throughput is orders of magnitude above that). Measured in
the soak; numbers in the README when pinned.

## State machines

Client: numeric states −6..3 identical to C (`ClientState` enum). Transitions
ported line-for-line from `netcode_client_update` /
`netcode_client_process_packet_internal`, including:
- `should_disconnect` latch → try next server address before error state
- connect token expiry measured as `time - connect_start_time >=
  (expire_timestamp - create_timestamp)`
- timeout disabled when `timeout_seconds <= 0` (dev mode)

Server: no state machine beyond running/stopped (deliberate, per upstream
notes). Per-client: connected/confirmed flags, disconnect reason recorded
BEFORE the callback fires. Connection request processing order is the
spec's order (size → version → protocol → expiry → predates-server-start →
decrypt → read → address-in-token → already-connected(addr) →
already-connected(id) → token history (full or already used) → full? denied :
add-mapping → challenge). The predates-server-start check refuses a token whose
expire timestamp is below server start time + `ServerConfig.MaxConnectTokenLifetime`.

## Timeout / replay invariants (must hold, red team should attack)

- Replay window advances ONLY after AEAD authentication succeeds
  (pre-decrypt `AlreadyReceived` is an optimization; the advance is
  post-decrypt). Applied only to packet types ≥ keep-alive (4,5,6).
- `AlreadyReceived` uses the overflow-safe form
  `most_recent >= SIZE && sequence <= most_recent - SIZE`.
- `ulong.MaxValue` is the empty-slot sentinel in the replay window: `ReadPacket`
  ignores an encrypted packet with that sequence, `AlreadyReceived` reports it
  as received, and `AdvanceSequence` ignores it.
- Encryption mapping expires after `timeout` seconds without access, or at
  `expire_time` (token timeout after request, cleared to −1 on connect).
- Global packet sequence starts at `1UL<<63` on every `Server.Start` (nonce
  disjointness vs per-client sequences starting at 0 under the same key).
- Connect token single-use history: constant-time worst-case scan; pending and
  consumed states; expiry timestamps; pending same-address retransmits only;
  no eviction while entries are unexpired; entry time is never refreshed.
- Client timeout uses `last_packet_receive_time + timeout < time`; server
  uses `<= time`. (Yes, they differ in the C source; ported as-is.)

## Test inventory

The runner (`tests/Tests.cs`, `Program.Main`) has 68 named tests in two tiers.
The default run is the unit tier (59 tests): it opens no OS sockets, never
sleeps, and fixes the clock at `TestConstants.TestUnixTime`. `--functional`
runs the functional tier (9 tests: client/server create, the three real UDP
socket connects, the two port-in-use creates, packet tagging, and the socket
zero-allocation check). `-- soak <n>` runs the bounded soak (`Soak` in
`tests/ClientServer.cs`) instead.

Same name as a `RUN_TEST` in netcode.c (at the interop pin): crypto_aead_vectors
(same golden bytes), queue, sequence, address, connect_token (private),
generate_connect_token_out_of_range (runtime check, not assert),
challenge_token, all 7 packet read/write tests, connect_token_public,
encryption_manager, replay_protection, network_simulator_determinism,
client_create and server_create (functional tier), server_restart_global_sequence,
client_error_connect_token_predates_server_start, client_server_connect
(simulator), ipv4/ipv6/dual socket connect (functional tier; real UDP
loopback), keep_alive, multiple_clients, multiple_servers, the six
client_error_* state tests, client/server side disconnect,
server_client_disconnect_reason, client_reconnect, disable_timeout, loopback,
packet_tagging (functional tier; also reads `IP_TOS` / `IPV6_TCLASS` back from
each socket; not checked on Windows, where tagging is a no-op).

Renamed or split from a C test: test_client_reconnect_used_connect_token
(C: test_client_reconnect_with_used_connect_token);
test_client_loopback_requires_callback and test_server_loopback_requires_callback
(C: test_loopback_callback_required); test_client_create_port_in_use and
test_server_create_port_in_use (the port-already-in-use blocks of C's
test_client_create_error and test_server_create_error, on ephemeral ports).

C `RUN_TEST` names with no test of that name in the C# runner: test_endian (no
endian-dependent code — explicit little-endian byte IO), test_runtime_guards,
test_init_and_defaults, test_client_create_error, test_server_create_error,
test_network_simulator_allocation_failure, test_connect_token_entries,
test_client_server_connection_request_retransmission,
test_client_server_replay_across_sessions, and the build-flag test
test_nonce_audit.

C# tests whose name is not a C `RUN_TEST`: test_socket_connection_reset_control
(`NetcodeSocket.ConfigureConnectionReset` error handling and disposal),
test_crypto_poly1305_vectors (RFC 8439 Section 2.5.2 and Appendix A.3 Poly1305
vectors), test_crypto_differential_bcl (managed-vs-BCL crypto differential),
test_socket_buffer_size_back_off (socket send/receive buffer size backoff),
test_key_cleanup (zeroization of temporary, retired and disposed key buffers),
FloatMultiplyAddRoundsTwice (FP contraction canary),
test_ipv6_traffic_class_option (`IPV6_TCLASS` socket option number per OS),
test_client_server_address_families (client address selection matches the
available socket family, without opening a socket),
test_connect_token_history (unit test of `ConnectTokenHistory`),
test_receive_packet_short_buffer (client and server `ReceivePacket` reject a
buffer smaller than `Protocol.MaxPacketSize`), test_unused_members_removed
(reflection guard that the removed internal members stay removed),
test_client_create_missing_override_callback and
test_server_create_missing_override_callback,
test_replay_protection_duplicate_packet and
test_replay_protection_failed_decrypt (replay protection through
`PacketIO.ReadPacket` within one session: duplicate datagrams rejected, failed
decrypts leaving the window unchanged), hostile fuzz (seeded, deterministic)
over every parse path — test_fuzz_read_packet_raw,
test_fuzz_packet_round_trip_corruption (ports the libFuzzer harnesses' logic),
test_fuzz_connect_token, test_fuzz_parse_address (replays embedded seeds from
the C repo's `fuzz/corpus/fuzz_parse_address`, plus external seeds when a
sibling `netcode` clone or `NETCODE_FUZZ_CORPUS` provides them) — and the
zero-allocation assertions test_zero_allocation_steady_state and
test_zero_allocation_socket_steady_state (functional tier).

## Interop gate

`compat/c/compat.c` `#include`s the real `netcode.c` (like the C fuzz
harnesses do) from a pinned clone, so it reaches internal write/encrypt
functions. Legs (all must pass, `scripts/interop.sh`):

1. **Goldens C→C#**: C writes, with fixed keys/nonces/timestamps: private
   token ciphertext, public token, challenge token ciphertext, every packet
   type ciphertext. C# byte-compares its own writes against them AND
   decrypts/parses the C bytes.
2. **Goldens C#→C**: the reverse.
3. **Session C server ↔ C# client**: token minted by C#, real UDP loopback,
   connect → payload echo N× → client-side disconnect; both sides assert
   observable behavior (states, client index, payload bytes).
4. **Session C# server ↔ C client**: token minted by C, reverse of 3.

CI pins the C clone to a fixed netcode ref (`47a156b1…` in
`.github/workflows/ci.yml`, netcode 1.4.8) and builds the C half with
`-ffp-contract=off`.
