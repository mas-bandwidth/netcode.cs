# netcode.cs port map

C# port of [mas-bandwidth/netcode](https://github.com/mas-bandwidth/netcode)
(C reference, version 1.4.8, protocol "NETCODE 1.02"). The WIRE is the C
library's, byte-exact; the API is idiomatic C#, mirroring the C library's
non-blocking update-loop model (games call `Update()` each frame — no async
redesign).

## Protocol objects → C# shapes

| C | C# | Notes |
|---|---|-------|
| `netcode_address_t` | `struct Address` | 18-byte value type: type (None/IPv4/IPv6), port, inline data. `Parse`/`TryParse`/`ToString` reproduce the C parser's observable behavior (strict dotted-quad IPv4, port suffix rules, the deliberately lenient `[::1`). |
| `netcode_connect_token_private_t` | `sealed class ConnectTokenPrivate` (internal) | read/write to the fixed 1024-byte buffer |
| `netcode_connect_token_t` (public 2048) | `sealed class ConnectToken` (internal parse) + `public static class ConnectTokenGenerator` | `Generate(...)` is the public mint API, signature mirrors `netcode_generate_connect_token` |
| `netcode_challenge_token_t` | `struct ChallengeToken` (internal) | 300-byte buffer, 8+256 payload |
| packet structs (7 types) | internal static `PacketIO.WritePacket` / `ReadPacket` over `Span<byte>` | no per-packet allocation: `ReadPacket` decrypts in place and returns type+sequence+payload span |
| `netcode_replay_protection_t` | `sealed class ReplayProtection` (internal) | 256-entry window, identical overflow-safe compare |
| `netcode_packet_queue_t` | `sealed class PacketQueue` (internal) | ring of 256; payload buffers come from a private fixed pool, not the GC |
| `netcode_encryption_manager_t` | `sealed class EncryptionManager` (internal) | flat arrays + linear scan, same as C — deliberate (attacker controls addresses; linear is the hardened choice, per upstream) |
| `netcode_connect_token_entry_t[]` | inside `Server` | constant-time worst-case scan; pending/consumed state, expiry timestamps, and history index carried by the encryption mapping |
| `netcode_network_simulator_t` | `public sealed class NetworkSimulator` | same xorshift64* RNG, same seed, so loss/jitter sequences match the C library run-for-run |
| `netcode_client_t` | `public sealed class Client` | states as `public enum ClientState` (same numeric values −6..3) |
| `netcode_server_t` | `public sealed class Server` | flat per-client arrays, max 256 clients, global sequence seeded `1UL<<63` on start AND stop→start (nonce-space separation — upstream 1.4.0 fix, every seeding site kept) |
| `netcode_init/term` | not needed | no WSAStartup / sodium_init equivalent in .NET; documented |
| `netcode_client_create_dual` | `Client` ctor with optional second address | same for `Server` |
| loopback APIs | ported | yojimbo parity |
| packet tagging | `EnablePacketTagging()` best-effort | IPv4 TOS + IPv6 TCLASS on unix/mac; Windows Qwave NOT ported (documented) |

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
ChaCha20 block/stream (RFC 8439), Poly1305 (64-bit limbs via `UInt128`),
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
spec's exact order (size → version → protocol → expiry → decrypt → read →
address-in-token → already-connected(addr) → already-connected(id) →
token-reuse → full? denied : add-mapping → challenge).

## Timeout / replay invariants (must hold, red team should attack)

- Replay window advances ONLY after AEAD authentication succeeds
  (pre-decrypt `AlreadyReceived` is an optimization; the advance is
  post-decrypt). Applied only to packet types ≥ keep-alive (4,5,6).
- `AlreadyReceived` uses the overflow-safe form
  `most_recent >= SIZE && sequence <= most_recent - SIZE`.
- Encryption mapping expires after `timeout` seconds without access, or at
  `expire_time` (token timeout after request, cleared to −1 on connect).
- Global packet sequence starts at `1UL<<63` on every `Server.Start` (nonce
  disjointness vs per-client sequences starting at 0 under the same key).
- Connect token single-use history: constant-time worst-case scan; pending and
  consumed states; expiry timestamps; pending same-address retransmits only;
  no eviction while entries are unexpired; entry time is never refreshed.
- Client timeout uses `last_packet_receive_time + timeout < time`; server
  uses `<= time`. (Yes, they differ in the C source; ported as-is.)

## Test inventory (test-for-test from netcode.c, minus C-specific)

Ported: crypto_aead_vectors (same golden bytes), queue, sequence, address,
connect_token (private), generate_connect_token_out_of_range (runtime check,
not assert), challenge_token, all 7 packet read/write tests,
connect_token_public, encryption_manager, replay_protection,
init_and_defaults (adapted), client/server create + create-error (adapted:
managed socket errors), network_simulator_determinism,
server_restart_global_sequence, client_server_connect (simulator),
ipv4/ipv6/dual socket connect (real UDP loopback), keep_alive,
multiple_clients, multiple_servers, all client error-state tests,
client/server side disconnect, disconnect_reason, reconnect,
disable_timeout, loopback. Dropped: test_endian (no endian-dependent code —
explicit little-endian byte IO), test_runtime_guards' assert-machinery parts
(no assert hooks in C#; the runtime guards themselves are tested),
packet_tagging (socket-option smoke only).

Added beyond the C suite: hostile fuzz (seeded, deterministic) over every
parse path — ReadPacket raw + round-trip-with-corruption (ports the libFuzzer
harnesses' logic), connect token public/private hostile reads, address parse
corpus from `netcode/fuzz/corpus`; zero-allocation assertions on the
steady-state packet paths; managed-vs-BCL crypto differential.

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

CI pins the C clone to a fixed netcode ref.
