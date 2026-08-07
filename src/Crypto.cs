/*
    Crypto.cs — the two AEAD constructions netcode uses on the wire.

    C# port of the slice of libsodium that the C reference implementation vendors
    (see sodium/NOTES.md in mas-bandwidth/netcode):

        crypto_aead_chacha20poly1305_ietf_{encrypt,decrypt}   (RFC 8439)
        crypto_aead_xchacha20poly1305_ietf_{encrypt,decrypt}  (HChaCha20 subkey + IETF)

    This is a single, fully managed production path — no platform primitive, no
    P/Invoke — so behavior is identical on every OS and TFM. The BCL's
    ChaCha20Poly1305 (where supported) is used by the test suite as a differential
    oracle only, never in production code.

    Constant-time discipline:
      - ChaCha20 and Poly1305 are add-rotate-xor / integer-multiply only: no
        secret-dependent branches, no secret-indexed table lookups.
      - The Poly1305 tag comparison is CryptographicOperations.FixedTimeEquals.
      - On decrypt, plaintext is only produced after the tag has verified
        (libsodium 1.0.22 orders verification before the stream xor; so do we).

    Copyright © 2026 Más Bandwidth LLC. Licensed under AGPL-3.0 (see LICENSE).
*/

using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace Netcode
{
    /// <summary>
    /// The AEAD primitives netcode uses: ChaCha20-Poly1305 (IETF, RFC 8439) for
    /// encrypted packets and challenge tokens, and XChaCha20-Poly1305 for the
    /// private connect token. Wire-identical to libsodium.
    /// </summary>
    internal static class Aead
    {
        public const int KeyBytes = 32;
        public const int MacBytes = 16;
        public const int NonceBytesIetf = 12;
        public const int NonceBytesX = 24;

        // ------------------------------------------------------------------
        // ChaCha20 core (RFC 8439). 32-bit counter, 96-bit nonce.
        // ------------------------------------------------------------------

        private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            a += b; d ^= a; d = BitOperations.RotateLeft(d, 16);
            c += d; b ^= c; b = BitOperations.RotateLeft(b, 12);
            a += b; d ^= a; d = BitOperations.RotateLeft(d, 8);
            c += d; b ^= c; b = BitOperations.RotateLeft(b, 7);
        }

        private static void ChaCha20Rounds(Span<uint> x)
        {
            for (int i = 0; i < 10; i++)
            {
                QuarterRound(ref x[0], ref x[4], ref x[8], ref x[12]);
                QuarterRound(ref x[1], ref x[5], ref x[9], ref x[13]);
                QuarterRound(ref x[2], ref x[6], ref x[10], ref x[14]);
                QuarterRound(ref x[3], ref x[7], ref x[11], ref x[15]);
                QuarterRound(ref x[0], ref x[5], ref x[10], ref x[15]);
                QuarterRound(ref x[1], ref x[6], ref x[11], ref x[12]);
                QuarterRound(ref x[2], ref x[7], ref x[8], ref x[13]);
                QuarterRound(ref x[3], ref x[4], ref x[9], ref x[14]);
            }
        }

        private const uint Sigma0 = 0x61707865; // "expa"
        private const uint Sigma1 = 0x3320646e; // "nd 3"
        private const uint Sigma2 = 0x79622d32; // "2-by"
        private const uint Sigma3 = 0x6b206574; // "te k"

        private static void InitState(Span<uint> state, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter)
        {
            state[0] = Sigma0;
            state[1] = Sigma1;
            state[2] = Sigma2;
            state[3] = Sigma3;
            for (int i = 0; i < 8; i++)
                state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(i * 4, 4));
            state[12] = counter;
            state[13] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(0, 4));
            state[14] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(4, 4));
            state[15] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(8, 4));
        }

        private static void Block(ReadOnlySpan<uint> state, Span<byte> keystream64)
        {
            Span<uint> x = stackalloc uint[16];
            state.CopyTo(x);
            ChaCha20Rounds(x);
            for (int i = 0; i < 16; i++)
                BinaryPrimitives.WriteUInt32LittleEndian(keystream64.Slice(i * 4, 4), x[i] + state[i]);
        }

        /// <summary>ChaCha20 stream xor: dst = src ^ keystream(key, nonce, counter...).
        /// dst and src may be the same span (in-place).</summary>
        internal static void ChaCha20Xor(Span<byte> dst, ReadOnlySpan<byte> src, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter)
        {
            Span<uint> state = stackalloc uint[16];
            InitState(state, key, nonce, counter);
            Span<byte> keystream = stackalloc byte[64];

            int offset = 0;
            int remaining = src.Length;
            while (remaining > 0)
            {
                Block(state, keystream);
                state[12]++;
                int n = remaining < 64 ? remaining : 64;
                for (int i = 0; i < n; i++)
                    dst[offset + i] = (byte)(src[offset + i] ^ keystream[i]);
                offset += n;
                remaining -= n;
            }

            CryptographicOperations.ZeroMemory(keystream);
            state.Clear();
        }

        // ------------------------------------------------------------------
        // HChaCha20 (the XChaCha20 subkey derivation). 16-byte input, 32-byte out.
        // ------------------------------------------------------------------

        internal static void HChaCha20(Span<byte> subkey32, ReadOnlySpan<byte> key, ReadOnlySpan<byte> input16)
        {
            Span<uint> x = stackalloc uint[16];
            x[0] = Sigma0;
            x[1] = Sigma1;
            x[2] = Sigma2;
            x[3] = Sigma3;
            for (int i = 0; i < 8; i++)
                x[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(i * 4, 4));
            for (int i = 0; i < 4; i++)
                x[12 + i] = BinaryPrimitives.ReadUInt32LittleEndian(input16.Slice(i * 4, 4));

            ChaCha20Rounds(x);

            // no final addition: HChaCha20 outputs words 0..3 and 12..15 directly
            for (int i = 0; i < 4; i++)
                BinaryPrimitives.WriteUInt32LittleEndian(subkey32.Slice(i * 4, 4), x[i]);
            for (int i = 0; i < 4; i++)
                BinaryPrimitives.WriteUInt32LittleEndian(subkey32.Slice(16 + i * 4, 4), x[12 + i]);

            x.Clear();
        }

        // ------------------------------------------------------------------
        // Poly1305 (donna-style 44-bit limbs over UInt128).
        // ------------------------------------------------------------------

        private struct Poly1305State
        {
            public ulong R0, R1, R2;
            public ulong S1, S2;
            public ulong H0, H1, H2;
            public ulong Pad0, Pad1;
        }

        private static void Poly1305Init(ref Poly1305State st, ReadOnlySpan<byte> key32)
        {
            ulong t0 = BinaryPrimitives.ReadUInt64LittleEndian(key32.Slice(0, 8));
            ulong t1 = BinaryPrimitives.ReadUInt64LittleEndian(key32.Slice(8, 8));

            // r &= 0xffffffc0ffffffc0ffffffc0fffffff, split into 44-bit limbs
            st.R0 = t0 & 0xffc0fffffffUL;
            st.R1 = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffffUL;
            st.R2 = (t1 >> 24) & 0x00ffffffc0fUL;

            st.S1 = st.R1 * 20; // (5 << 2)
            st.S2 = st.R2 * 20;

            st.H0 = 0;
            st.H1 = 0;
            st.H2 = 0;

            st.Pad0 = BinaryPrimitives.ReadUInt64LittleEndian(key32.Slice(16, 8));
            st.Pad1 = BinaryPrimitives.ReadUInt64LittleEndian(key32.Slice(24, 8));
        }

        private static void Poly1305Blocks(ref Poly1305State st, ReadOnlySpan<byte> m, bool final)
        {
            ulong hibit = final ? 0 : 1UL << 40;
            ulong h0 = st.H0, h1 = st.H1, h2 = st.H2;
            ulong r0 = st.R0, r1 = st.R1, r2 = st.R2;
            ulong s1 = st.S1, s2 = st.S2;

            while (m.Length >= 16)
            {
                ulong t0 = BinaryPrimitives.ReadUInt64LittleEndian(m.Slice(0, 8));
                ulong t1 = BinaryPrimitives.ReadUInt64LittleEndian(m.Slice(8, 8));

                h0 += t0 & 0xfffffffffffUL;
                h1 += ((t0 >> 44) | (t1 << 20)) & 0xfffffffffffUL;
                h2 += ((t1 >> 24) & 0x3ffffffffffUL) | hibit;

                UInt128 d0 = (UInt128)h0 * r0 + (UInt128)h1 * s2 + (UInt128)h2 * s1;
                UInt128 d1 = (UInt128)h0 * r1 + (UInt128)h1 * r0 + (UInt128)h2 * s2;
                UInt128 d2 = (UInt128)h0 * r2 + (UInt128)h1 * r1 + (UInt128)h2 * r0;

                ulong c = (ulong)(d0 >> 44); h0 = (ulong)d0 & 0xfffffffffffUL;
                d1 += c; c = (ulong)(d1 >> 44); h1 = (ulong)d1 & 0xfffffffffffUL;
                d2 += c; c = (ulong)(d2 >> 42); h2 = (ulong)d2 & 0x3ffffffffffUL;
                h0 += c * 5; c = h0 >> 44; h0 &= 0xfffffffffffUL;
                h1 += c;

                m = m.Slice(16);
            }

            st.H0 = h0;
            st.H1 = h1;
            st.H2 = h2;
        }

        private static void Poly1305Update(ref Poly1305State st, ReadOnlySpan<byte> data, Span<byte> scratch16, ref int scratchLen)
        {
            // fill a partial block first
            if (scratchLen > 0)
            {
                int want = 16 - scratchLen;
                if (want > data.Length)
                    want = data.Length;
                data.Slice(0, want).CopyTo(scratch16.Slice(scratchLen));
                scratchLen += want;
                data = data.Slice(want);
                if (scratchLen == 16)
                {
                    Poly1305Blocks(ref st, scratch16, final: false);
                    scratchLen = 0;
                }
            }

            int whole = data.Length & ~15;
            if (whole > 0)
            {
                Poly1305Blocks(ref st, data.Slice(0, whole), final: false);
                data = data.Slice(whole);
            }

            if (data.Length > 0)
            {
                data.CopyTo(scratch16);
                scratchLen = data.Length;
            }
        }

        private static void Poly1305Finish(ref Poly1305State st, Span<byte> scratch16, int scratchLen, Span<byte> mac16)
        {
            if (scratchLen > 0)
            {
                scratch16[scratchLen] = 1;
                for (int i = scratchLen + 1; i < 16; i++)
                    scratch16[i] = 0;
                Poly1305Blocks(ref st, scratch16, final: true);
            }

            ulong h0 = st.H0, h1 = st.H1, h2 = st.H2;

            ulong c = h1 >> 44; h1 &= 0xfffffffffffUL;
            h2 += c; c = h2 >> 42; h2 &= 0x3ffffffffffUL;
            h0 += c * 5; c = h0 >> 44; h0 &= 0xfffffffffffUL;
            h1 += c; c = h1 >> 44; h1 &= 0xfffffffffffUL;
            h2 += c; c = h2 >> 42; h2 &= 0x3ffffffffffUL;
            h0 += c * 5; c = h0 >> 44; h0 &= 0xfffffffffffUL;
            h1 += c;

            // compute h + -p
            ulong g0 = h0 + 5; c = g0 >> 44; g0 &= 0xfffffffffffUL;
            ulong g1 = h1 + c; c = g1 >> 44; g1 &= 0xfffffffffffUL;
            ulong g2 = unchecked(h2 + c - (1UL << 42));

            // select h if h < p, else h - p (constant time)
            c = (g2 >> 63) - 1;
            g0 &= c; g1 &= c; g2 &= c;
            ulong nc = ~c;
            h0 = (h0 & nc) | g0;
            h1 = (h1 & nc) | g1;
            h2 = (h2 & nc) | g2;

            // h += pad
            ulong t0 = st.Pad0, t1 = st.Pad1;
            h0 += t0 & 0xfffffffffffUL; c = h0 >> 44; h0 &= 0xfffffffffffUL;
            h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffffUL) + c; c = h1 >> 44; h1 &= 0xfffffffffffUL;
            h2 += ((t1 >> 24) & 0x3ffffffffffUL) + c; h2 &= 0x3ffffffffffUL;

            // mac = h % 2^128
            h0 |= h1 << 44;
            h1 = (h1 >> 20) | (h2 << 24);
            BinaryPrimitives.WriteUInt64LittleEndian(mac16.Slice(0, 8), h0);
            BinaryPrimitives.WriteUInt64LittleEndian(mac16.Slice(8, 8), h1);

            st.H0 = 0; st.H1 = 0; st.H2 = 0;
            st.R0 = 0; st.R1 = 0; st.R2 = 0;
            st.S1 = 0; st.S2 = 0;
            st.Pad0 = 0; st.Pad1 = 0;
        }

        // ------------------------------------------------------------------
        // AEAD construction (RFC 8439 / libsodium chacha20poly1305_ietf)
        // ------------------------------------------------------------------

        private static readonly byte[] ZeroPad = new byte[16];

        private static void ComputeTag(
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> additional,
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> nonce12,
            Span<byte> tag16)
        {
            // poly key = first 32 bytes of the chacha20 keystream at counter 0
            Span<byte> polyKey = stackalloc byte[32];
            polyKey.Clear();
            ChaCha20Xor(polyKey, polyKey, key, nonce12, 0);

            Poly1305State st = default;
            Poly1305Init(ref st, polyKey);
            Span<byte> scratch = stackalloc byte[16];
            int scratchLen = 0;

            Poly1305Update(ref st, additional, scratch, ref scratchLen);
            int adPad = (16 - (additional.Length & 15)) & 15;
            if (adPad > 0)
                Poly1305Update(ref st, ZeroPad.AsSpan(0, adPad), scratch, ref scratchLen);

            Poly1305Update(ref st, ciphertext, scratch, ref scratchLen);
            int ctPad = (16 - (ciphertext.Length & 15)) & 15;
            if (ctPad > 0)
                Poly1305Update(ref st, ZeroPad.AsSpan(0, ctPad), scratch, ref scratchLen);

            Span<byte> lengths = stackalloc byte[16];
            BinaryPrimitives.WriteUInt64LittleEndian(lengths.Slice(0, 8), (ulong)additional.Length);
            BinaryPrimitives.WriteUInt64LittleEndian(lengths.Slice(8, 8), (ulong)ciphertext.Length);
            Poly1305Update(ref st, lengths, scratch, ref scratchLen);

            Poly1305Finish(ref st, scratch, scratchLen, tag16);

            CryptographicOperations.ZeroMemory(polyKey);
        }

        /// <summary>
        /// Encrypt in place: <paramref name="buffer"/> holds messageLength bytes of
        /// plaintext on entry and messageLength + 16 bytes of ciphertext ‖ tag on
        /// return. IETF construction, 12-byte nonce. Matches
        /// crypto_aead_chacha20poly1305_ietf_encrypt with combined MAC.
        /// </summary>
        public static void EncryptIetf(Span<byte> buffer, int messageLength, ReadOnlySpan<byte> additional, ReadOnlySpan<byte> nonce12, ReadOnlySpan<byte> key)
        {
            Span<byte> message = buffer.Slice(0, messageLength);
            ChaCha20Xor(message, message, key, nonce12, 1);
            ComputeTag(message, additional, key, nonce12, buffer.Slice(messageLength, MacBytes));
        }

        /// <summary>
        /// Decrypt in place: <paramref name="buffer"/> holds ciphertext ‖ tag on
        /// entry; on success the first bufferLength − 16 bytes hold plaintext.
        /// Returns false (and writes nothing) if authentication fails.
        /// </summary>
        public static bool DecryptIetf(Span<byte> buffer, int bufferLength, ReadOnlySpan<byte> additional, ReadOnlySpan<byte> nonce12, ReadOnlySpan<byte> key)
        {
            if (bufferLength < MacBytes)
                return false;

            int messageLength = bufferLength - MacBytes;
            Span<byte> ciphertext = buffer.Slice(0, messageLength);

            Span<byte> expectedTag = stackalloc byte[MacBytes];
            ComputeTag(ciphertext, additional, key, nonce12, expectedTag);

            // authenticate BEFORE producing any plaintext
            if (!CryptographicOperations.FixedTimeEquals(expectedTag, buffer.Slice(messageLength, MacBytes)))
                return false;

            ChaCha20Xor(ciphertext, ciphertext, key, nonce12, 1);
            return true;
        }

        /// <summary>
        /// XChaCha20-Poly1305 encrypt in place (24-byte nonce). Matches
        /// crypto_aead_xchacha20poly1305_ietf_encrypt with combined MAC.
        /// </summary>
        public static void EncryptX(Span<byte> buffer, int messageLength, ReadOnlySpan<byte> additional, ReadOnlySpan<byte> nonce24, ReadOnlySpan<byte> key)
        {
            Span<byte> subkey = stackalloc byte[KeyBytes];
            Span<byte> ietfNonce = stackalloc byte[NonceBytesIetf];
            DeriveXNonce(nonce24, key, subkey, ietfNonce);
            EncryptIetf(buffer, messageLength, additional, ietfNonce, subkey);
            CryptographicOperations.ZeroMemory(subkey);
        }

        /// <summary>XChaCha20-Poly1305 decrypt in place (24-byte nonce).</summary>
        public static bool DecryptX(Span<byte> buffer, int bufferLength, ReadOnlySpan<byte> additional, ReadOnlySpan<byte> nonce24, ReadOnlySpan<byte> key)
        {
            Span<byte> subkey = stackalloc byte[KeyBytes];
            Span<byte> ietfNonce = stackalloc byte[NonceBytesIetf];
            DeriveXNonce(nonce24, key, subkey, ietfNonce);
            bool ok = DecryptIetf(buffer, bufferLength, additional, ietfNonce, subkey);
            CryptographicOperations.ZeroMemory(subkey);
            return ok;
        }

        private static void DeriveXNonce(ReadOnlySpan<byte> nonce24, ReadOnlySpan<byte> key, Span<byte> subkey, Span<byte> ietfNonce)
        {
            HChaCha20(subkey, key, nonce24.Slice(0, 16));
            ietfNonce.Slice(0, 4).Clear();
            nonce24.Slice(16, 8).CopyTo(ietfNonce.Slice(4));
        }
    }
}
