# Post-release hardening — netcode.cs

From the 2026-08-07 red/blue security review (five adversarial lenses, two
independent cryptography passes under different models). Verdict was **READY** —
zero surviving findings after adversarial refutation. These are defense-in-depth
items to close post-release, none a release blocker.

1. **Zeroize long-lived key material on disconnect/Stop.** `EncryptionManager`
   `SendKey`/`ReceiveKey` (byte[]), `_challengeKey`, and `_connectToken.PrivateData`
   linger on the GC heap while the ephemeral subkey / keystream / polyKey / Poly1305
   state are already cleared. This matches the C reference and requires a separate
   memory-disclosure primitive to exploit, but the asymmetry is worth closing.

2. **Give the socket layer a dedicated review pass.** `NetcodeSocket`, the packet
   simulator, and the loopback client/server paths sit off the on-the-wire
   crypto/parse trust boundary and were not line-diffed against the C. They should
   not stay unexamined indefinitely.

3. **Differential vectors run live** — satisfied: the `C wire compatibility` CI job
   builds the real `netcode.c` and requires byte-identical goldens both directions
   on every push. Keep it green; it is the proof under the READY verdict.
