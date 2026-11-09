/*
    Tests.cs

    Console test runner for the C# netcode port. Zero third-party dependencies,
    including test frameworks (family value): each test prints its name, a failed
    check prints and exits nonzero — the exact shape of check / RUN_TEST in the C
    reference implementation.

    The suite is a test-for-test port of the C suite in netcode.c (minus
    test_endian, irrelevant with explicit little endian primitives, and the
    assert-hook machinery, which does not exist in C#), plus hostile fuzz tests
    over every parse path, a zero-allocation assertion on the steady-state packet
    paths, and a differential test of the managed crypto against the BCL's
    ChaCha20Poly1305 where the platform supports it (Hostile.cs).
*/

using System;
using System.Net.Sockets;
using System.Runtime.CompilerServices;

namespace Netcode.Tests;

internal static class Check
{
    public static void That(bool condition, [CallerFilePath] string file = "", [CallerLineNumber] int line = 0, [CallerArgumentExpression(nameof(condition))] string expr = "")
    {
        if (!condition)
        {
            Console.WriteLine($"check failed: ( {expr} ), {file}:{line}");
            Environment.Exit(1);
        }
    }
}

internal static class TestConstants
{
    public const ulong TestProtocolId = 0x1122334455667788UL;
    public const ulong TestClientId = 0x1UL;
    public const int TestServerPort = 40000;
    public const int TestConnectTokenExpiry = 30;
    public const int TestTimeoutSeconds = 15;

    // TEST KEY ONLY — same fixed key as the C reference test suite. Obviously
    // non-production: it is published in two public repositories.
    public static readonly byte[] PrivateKey =
    {
        0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea,
        0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
        0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
        0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1,
    };
}

// deterministic xorshift64* rng for seeded "random" test data (never the CSPRNG:
// hostile tests must reproduce exactly from the printed seed)
internal sealed class TestRng
{
    private ulong _state;

    public TestRng(ulong seed) => _state = seed != 0 ? seed : 1;

    public ulong NextUInt64()
    {
        ulong x = _state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        _state = x;
        return unchecked(x * 0x2545F4914F6CDD1DUL);
    }

    public int Next(int maxExclusive) => (int)(NextUInt64() % (ulong)maxExclusive);

    public void Fill(Span<byte> data)
    {
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)NextUInt64();
    }
}

internal static class Program
{
    private static string? _filter;

    private static void RunTest(string name, Action test)
    {
        if (_filter != null && !name.Contains(_filter, StringComparison.OrdinalIgnoreCase))
            return;
        Console.WriteLine(name);
        test();
    }

    private static int Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "soak")
        {
            int iterations = args.Length > 1 ? int.Parse(args[1]) : 1000;
            return Soak.Run(iterations);
        }

        if (args.Length > 0)
            _filter = args[0];

        Console.WriteLine("[netcode.cs tests]\n");

        RunTest("test_socket_connection_reset_control", CoreTests.TestSocketConnectionResetControl);

        RunTest("test_crypto_aead_vectors", CoreTests.TestCryptoAeadVectors);
        RunTest("test_crypto_poly1305_vectors", CoreTests.TestCryptoPoly1305Vectors);
        RunTest("test_crypto_differential_bcl", Hostile.TestCryptoDifferentialBcl);
        RunTest("test_queue", CoreTests.TestQueue);
        RunTest("test_sequence", CoreTests.TestSequence);
        RunTest("test_socket_buffer_size_back_off", CoreTests.TestSocketBufferSizeBackOff);
        RunTest("test_address", CoreTests.TestAddress);
        RunTest("test_connect_token", CoreTests.TestConnectToken);
        RunTest("test_generate_connect_token_out_of_range", CoreTests.TestGenerateConnectTokenOutOfRange);
        RunTest("test_challenge_token", CoreTests.TestChallengeToken);
        RunTest("test_connection_request_packet", CoreTests.TestConnectionRequestPacket);
        RunTest("test_connection_denied_packet", () => CoreTests.TestEmptyPacket(PacketType.ConnectionDenied));
        RunTest("test_connection_challenge_packet", () => CoreTests.TestChallengeResponsePacket(PacketType.ConnectionChallenge));
        RunTest("test_connection_response_packet", () => CoreTests.TestChallengeResponsePacket(PacketType.ConnectionResponse));
        RunTest("test_connection_keep_alive_packet", CoreTests.TestConnectionKeepAlivePacket);
        RunTest("test_connection_payload_packet", CoreTests.TestConnectionPayloadPacket);
        RunTest("test_connection_disconnect_packet", () => CoreTests.TestEmptyPacket(PacketType.ConnectionDisconnect));
        RunTest("test_connect_token_public", CoreTests.TestConnectTokenPublic);
        RunTest("test_key_cleanup", CoreTests.TestKeyCleanup);
        RunTest("test_encryption_manager", CoreTests.TestEncryptionManager);
        RunTest("test_replay_protection", CoreTests.TestReplayProtection);
        RunTest("test_network_simulator_determinism", CoreTests.TestNetworkSimulatorDeterminism);
        RunTest("FloatMultiplyAddRoundsTwice", CoreTests.FloatMultiplyAddRoundsTwice);
        RunTest("test_ipv6_traffic_class_option", CoreTests.TestIpv6TrafficClassOption);
        RunTest("test_client_create", ClientServerTests.TestClientCreate);
        RunTest("test_server_create", ClientServerTests.TestServerCreate);
        RunTest("test_server_restart_global_sequence", ClientServerTests.TestServerRestartGlobalSequence);
        RunTest("test_connect_token_history", ClientServerTests.TestConnectTokenHistory);
        RunTest("test_client_reconnect_used_connect_token", ClientServerTests.TestClientReconnectUsedConnectToken);
        RunTest("test_client_error_connect_token_predates_server_start", ClientServerTests.TestClientErrorConnectTokenPredatesServerStart);
        RunTest("test_client_server_connect", ClientServerTests.TestClientServerConnect);
        RunTest("test_client_server_ipv4_socket_connect", ClientServerTests.TestClientServerIpv4SocketConnect);
        RunTest("test_client_server_ipv6_socket_connect", ClientServerTests.TestClientServerIpv6SocketConnect);
        RunTest("test_client_server_dual_socket_connect", ClientServerTests.TestClientServerDualSocketConnect);
        RunTest("test_client_server_keep_alive", ClientServerTests.TestClientServerKeepAlive);
        RunTest("test_client_server_multiple_clients", ClientServerTests.TestClientServerMultipleClients);
        RunTest("test_client_server_multiple_servers", ClientServerTests.TestClientServerMultipleServers);
        RunTest("test_client_error_connect_token_expired", ClientServerTests.TestClientErrorConnectTokenExpired);
        RunTest("test_client_error_invalid_connect_token", ClientServerTests.TestClientErrorInvalidConnectToken);
        RunTest("test_client_error_connection_timed_out", ClientServerTests.TestClientErrorConnectionTimedOut);
        RunTest("test_client_error_connection_response_timeout", ClientServerTests.TestClientErrorConnectionResponseTimeout);
        RunTest("test_client_error_connection_request_timeout", ClientServerTests.TestClientErrorConnectionRequestTimeout);
        RunTest("test_client_error_connection_denied", ClientServerTests.TestClientErrorConnectionDenied);
        RunTest("test_client_side_disconnect", ClientServerTests.TestClientSideDisconnect);
        RunTest("test_server_side_disconnect", ClientServerTests.TestServerSideDisconnect);
        RunTest("test_server_client_disconnect_reason", ClientServerTests.TestServerClientDisconnectReason);
        RunTest("test_client_reconnect", ClientServerTests.TestClientReconnect);
        RunTest("test_disable_timeout", ClientServerTests.TestDisableTimeout);
        RunTest("test_loopback", ClientServerTests.TestLoopback);
        RunTest("test_receive_packet_short_buffer", ReceiveBufferTests.TestReceivePacketShortBuffer);
        RunTest("test_client_create_missing_override_callback", ClientServerTests.TestClientCreateMissingOverrideCallback);
        RunTest("test_server_create_missing_override_callback", ClientServerTests.TestServerCreateMissingOverrideCallback);
        RunTest("test_client_loopback_requires_callback", ClientServerTests.TestClientLoopbackRequiresCallback);
        RunTest("test_server_loopback_requires_callback", ClientServerTests.TestServerLoopbackRequiresCallback);

        // replay protection within a session (unit), port-in-use create errors and
        // packet tagging (functional: real loopback sockets on ephemeral ports)
        RunTest("test_replay_protection_duplicate_packet", SessionReplayTests.TestReplayProtectionDuplicatePacket);
        RunTest("test_replay_protection_failed_decrypt", SessionReplayTests.TestReplayProtectionFailedDecrypt);
        RunTest("test_client_create_port_in_use", ClientServerTests.TestClientCreatePortInUse);
        RunTest("test_server_create_port_in_use", ClientServerTests.TestServerCreatePortInUse);
        RunTest("test_packet_tagging", ClientServerTests.TestPacketTagging);

        RunTest("test_fuzz_read_packet_raw", Hostile.TestFuzzReadPacketRaw);
        RunTest("test_fuzz_packet_round_trip_corruption", Hostile.TestFuzzPacketRoundTripCorruption);
        RunTest("test_fuzz_connect_token", Hostile.TestFuzzConnectToken);
        RunTest("test_fuzz_parse_address", Hostile.TestFuzzParseAddress);
        RunTest("test_zero_allocation_steady_state", Hostile.TestZeroAllocationSteadyState);
        RunTest("test_zero_allocation_socket_steady_state", Hostile.TestZeroAllocationSocketSteadyState);

        Console.WriteLine("\nAll tests passed.");
        return 0;
    }
}

internal static class CoreTests
{
    private sealed class ControlHandle : IDisposable
    {
        public int DisposeCount;
        public void Dispose() => DisposeCount++;
    }

    public static void TestSocketConnectionResetControl()
    {
        var failedHandle = new ControlHandle();
        int controlCalls = 0;
        NetcodeSocket.CreateError error = NetcodeSocket.ConfigureConnectionReset(failedHandle, () =>
        {
            controlCalls++;
            throw new SocketException((int)SocketError.OperationNotSupported);
        });
        Check.That(error == NetcodeSocket.CreateError.CreateFailed);
        Check.That(controlCalls == 1);
        Check.That(failedHandle.DisposeCount == 1);

        var successfulHandle = new ControlHandle();
        error = NetcodeSocket.ConfigureConnectionReset(successfulHandle, () => controlCalls++);
        Check.That(error == NetcodeSocket.CreateError.None);
        Check.That(controlCalls == 2);
        Check.That(successfulHandle.DisposeCount == 0);
    }

    // Canary inputs for FloatMultiplyAddRoundsTwice. Deliberately mutable static
    // fields, not constants: the JIT must not be able to fold the test expression
    // at compile time, or the canary would prove nothing about the runtime.
    private static float _canaryFloatA = BitConverter.Int32BitsToSingle(0x3F800800);
    private static float _canaryFloatC = BitConverter.Int32BitsToSingle(unchecked((int)0xBF801000));
    private static double _canaryDoubleA = BitConverter.Int64BitsToDouble(0x3FF0000002000000L);
    private static double _canaryDoubleC = BitConverter.Int64BitsToDouble(unchecked((long)0xBFF0000004000000UL));

    public static void FloatMultiplyAddRoundsTwice()
    {
        // The estate rule is that network libraries build without floating-point
        // contraction: every operation rounds on its own, so results agree across
        // implementations and builds. The C half of the interop gate is compiled
        // with -ffp-contract=off (scripts/interop.sh); C# rounds each operation
        // and does not contract. These pairs are chosen so a single fused
        // multiply-add (one rounding) gives 0x33800000 / 0x3C90000000000000,
        // while two roundings give zero. A failure here means a runtime, a build
        // setting or a hand-written MathF.FusedMultiplyAdd changed the
        // simulator's or the timers' arithmetic.

        float a = _canaryFloatA;
        float b = _canaryFloatA;
        float c = _canaryFloatC;
        Check.That(BitConverter.SingleToInt32Bits(a * b + c) == 0x00000000);

        double da = _canaryDoubleA;
        double db = _canaryDoubleA;
        double dc = _canaryDoubleC;
        Check.That(BitConverter.DoubleToInt64Bits(da * db + dc) == 0L);
    }

    public static void TestIpv6TrafficClassOption()
    {
        // IPV6_TCLASS as each OS's own headers define it
        Check.That(NetcodeSocket.Ipv6TrafficClassOption(NetcodeSocket.SocketOS.Linux) == 67);
        Check.That(NetcodeSocket.Ipv6TrafficClassOption(NetcodeSocket.SocketOS.Android) == 67);
        Check.That(NetcodeSocket.Ipv6TrafficClassOption(NetcodeSocket.SocketOS.MacOS) == 36);
        Check.That(NetcodeSocket.Ipv6TrafficClassOption(NetcodeSocket.SocketOS.IOS) == 36);
        Check.That(NetcodeSocket.Ipv6TrafficClassOption(NetcodeSocket.SocketOS.MacCatalyst) == 36);
        Check.That(NetcodeSocket.Ipv6TrafficClassOption(NetcodeSocket.SocketOS.TvOS) == 36);
        Check.That(NetcodeSocket.Ipv6TrafficClassOption(NetcodeSocket.SocketOS.FreeBSD) == 61);

        // no known option number: IPv6 tagging is skipped
        Check.That(NetcodeSocket.Ipv6TrafficClassOption(NetcodeSocket.SocketOS.Other) == -1);
    }

    public static void TestCryptoAeadVectors()
    {
        // Known-answer test pinned to the same golden bytes as netcode.c's
        // test_crypto_aead_vectors (generated from libsodium reference output).
        // A golden failure here means the managed crypto no longer agrees with
        // libsodium, which would break wire compatibility with every other
        // netcode implementation.

        byte[] katKey =
        {
            0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,
            0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
            0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,
        };
        byte[] katAd = { 0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xca,0xcb };
        byte[] katMsg =
        {
            0x79,0x6f,0x6a,0x69,0x6d,0x62,0x6f,0x20,0x76,0x65,0x6e,0x64,0x6f,0x72,0x65,0x64,0x20,0x6c,0x69,0x62,
            0x73,0x6f,0x64,0x69,0x75,0x6d,0x20,0x41,0x45,0x41,0x44,0x20,0x6b,0x6e,0x6f,0x77,0x6e,0x2d,0x61,0x6e,
            0x73,0x77,0x65,0x72,0x20,0x74,0x65,0x73,0x74,0x20,0x76,0x65,0x63,0x74,0x6f,0x72,0x21,0x21,
        };
        byte[] katNpubIetf = { 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab };
        byte[] katCtIetf =
        {
            0xd5,0xae,0xb1,0x85,0x15,0x8b,0x07,0xb3,0x01,0x15,0xf0,0x59,
            0xb4,0x4e,0x9d,0x45,0x91,0x58,0xab,0xff,0xaf,0xbd,0x81,0x4f,
            0xbf,0x52,0xc2,0x4c,0xa1,0x5e,0x60,0x5f,0x58,0x63,0x31,0x96,
            0xda,0x90,0x07,0x63,0xb9,0x0c,0x21,0x46,0xf2,0xe4,0x65,0x96,
            0x7a,0x81,0x7f,0xa2,0x5d,0xd1,0x79,0xf6,0x9b,0x18,0x5d,0xe0,
            0xb6,0x57,0x93,0xbe,0x8c,0xb5,0xa9,0x75,0x98,0xa4,0x6f,0xd5,
            0xbe,0x9d,
        };
        byte[] katNpubXChaCha =
        {
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,
            0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        };
        byte[] katCtXChaCha =
        {
            0x2b,0x24,0x83,0x2a,0x6c,0x9e,0x21,0x02,0x2a,0x14,0x32,0x56,
            0x4b,0x27,0x37,0x92,0x24,0x40,0xa9,0x92,0xd3,0x53,0xa7,0xa5,
            0x64,0xd3,0x8e,0x0c,0x75,0x79,0x75,0x3f,0xca,0x82,0xfa,0x85,
            0xf0,0xa6,0xac,0x08,0x9a,0x25,0xf1,0x8f,0x42,0x20,0x70,0x8e,
            0x38,0x25,0xd1,0x08,0x45,0x81,0x75,0x18,0xe4,0xd1,0x88,0xbd,
            0x92,0xfa,0x84,0xdc,0xd6,0xa3,0x9a,0x67,0x52,0x91,0x62,0xf4,
            0x86,0x7b,
        };

        // ChaCha20-Poly1305 (IETF) — the construction netcode uses on the wire

        byte[] buffer = new byte[128];
        katMsg.CopyTo(buffer, 0);
        Aead.EncryptIetf(buffer, katMsg.Length, katAd, katNpubIetf, katKey);
        Check.That(buffer.AsSpan(0, katCtIetf.Length).SequenceEqual(katCtIetf));

        Check.That(Aead.DecryptIetf(buffer, katCtIetf.Length, katAd, katNpubIetf, katKey));
        Check.That(buffer.AsSpan(0, katMsg.Length).SequenceEqual(katMsg));

        // a tampered ciphertext must be rejected, and the buffer must be untouched
        // (plaintext must not be produced before authentication has completed)

        katMsg.CopyTo(buffer, 0);
        Aead.EncryptIetf(buffer, katMsg.Length, katAd, katNpubIetf, katKey);
        buffer[0] ^= 0x01;
        byte[] tampered = (byte[])buffer.Clone();
        Check.That(!Aead.DecryptIetf(buffer, katCtIetf.Length, katAd, katNpubIetf, katKey));
        Check.That(buffer.AsSpan().SequenceEqual(tampered));

        // XChaCha20-Poly1305

        Array.Clear(buffer);
        katMsg.CopyTo(buffer, 0);
        Aead.EncryptX(buffer, katMsg.Length, katAd, katNpubXChaCha, katKey);
        Check.That(buffer.AsSpan(0, katCtXChaCha.Length).SequenceEqual(katCtXChaCha));

        Check.That(Aead.DecryptX(buffer, katCtXChaCha.Length, katAd, katNpubXChaCha, katKey));
        Check.That(buffer.AsSpan(0, katMsg.Length).SequenceEqual(katMsg));

        katMsg.CopyTo(buffer, 0);
        Aead.EncryptX(buffer, katMsg.Length, katAd, katNpubXChaCha, katKey);
        buffer[0] ^= 0x01;
        Check.That(!Aead.DecryptX(buffer, katCtXChaCha.Length, katAd, katNpubXChaCha, katKey));

        // a tampered tag (not just ciphertext) must also be rejected

        katMsg.CopyTo(buffer, 0);
        Aead.EncryptIetf(buffer, katMsg.Length, katAd, katNpubIetf, katKey);
        buffer[katCtIetf.Length - 1] ^= 0x80;
        Check.That(!Aead.DecryptIetf(buffer, katCtIetf.Length, katAd, katNpubIetf, katKey));
    }

    public static void TestCryptoPoly1305Vectors()
    {
        // RFC 8439 Section 2.5.2 and Appendix A.3, bytes as published. Keys are
        // r ‖ s; vectors 5-11 are the RFC's limb-carry and final-reduction edge
        // cases (accumulator at or just below 2^130 - 5, s overflowing 2^128).

        const string ietfText =
            "416e79207375626d697373696f6e20746f20746865204945544620696e74656e" +
            "6465642062792074686520436f6e7472696275746f7220666f72207075626c69" +
            "636174696f6e20617320616c6c206f722070617274206f6620616e2049455446" +
            "20496e7465726e65742d4472616674206f722052464320616e6420616e792073" +
            "746174656d656e74206d6164652077697468696e2074686520636f6e74657874" +
            "206f6620616e204945544620616374697669747920697320636f6e7369646572" +
            "656420616e20224945544620436f6e747269627574696f6e222e205375636820" +
            "73746174656d656e747320696e636c756465206f72616c2073746174656d656e" +
            "747320696e20494554462073657373696f6e732c2061732077656c6c20617320" +
            "7772697474656e20616e6420656c656374726f6e696320636f6d6d756e696361" +
            "74696f6e73206d61646520617420616e792074696d65206f7220706c6163652c" +
            "207768696368206172652061646472657373656420746f";

        string[][] vectors =
        {
            // Section 2.5.2
            new[]
            {
                "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
                "43727970746f6772617068696320466f72756d2052657365617263682047726f7570",
                "a8061dc1305136c6c22b8baf0c0127a9",
            },
            // A.3 #1
            new[]
            {
                "0000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000",
            },
            // A.3 #2
            new[]
            {
                "0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e",
                ietfText,
                "36e5f6b5c5e06070f0efca96227a863e",
            },
            // A.3 #3
            new[]
            {
                "36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000",
                ietfText,
                "f3477e7cd95417af89a6b8794c310cf0",
            },
            // A.3 #4
            new[]
            {
                "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
                "2754776173206272696c6c69672c20616e642074686520736c6974687920746f" +
                "7665730a446964206779726520616e642067696d626c6520696e207468652077" +
                "6162653a0a416c6c206d696d737920776572652074686520626f726f676f7665" +
                "732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
                "4541669a7eaaee61e708dc7cbcc5eb62",
            },
            // A.3 #5: partially reduced final result not fully reduced
            new[]
            {
                "02000000000000000000000000000000" + "00000000000000000000000000000000",
                "ffffffffffffffffffffffffffffffff",
                "03000000000000000000000000000000",
            },
            // A.3 #6: addition of s overflows modulo 2^128
            new[]
            {
                "02000000000000000000000000000000" + "ffffffffffffffffffffffffffffffff",
                "02000000000000000000000000000000",
                "03000000000000000000000000000000",
            },
            // A.3 #7: data limb all ones with carry from lower limb
            new[]
            {
                "01000000000000000000000000000000" + "00000000000000000000000000000000",
                "ffffffffffffffffffffffffffffffff" +
                "f0ffffffffffffffffffffffffffffff" +
                "11000000000000000000000000000000",
                "05000000000000000000000000000000",
            },
            // A.3 #8: polynomial result exactly 2^130 - 5
            new[]
            {
                "01000000000000000000000000000000" + "00000000000000000000000000000000",
                "ffffffffffffffffffffffffffffffff" +
                "fbfefefefefefefefefefefefefefefe" +
                "01010101010101010101010101010101",
                "00000000000000000000000000000000",
            },
            // A.3 #9: polynomial result exactly 2^130 - 6
            new[]
            {
                "02000000000000000000000000000000" + "00000000000000000000000000000000",
                "fdffffffffffffffffffffffffffffff",
                "faffffffffffffffffffffffffffffff",
            },
            // A.3 #10: 5*H+L reduction produces a 131-bit intermediate result
            new[]
            {
                "01000000000000000400000000000000" + "00000000000000000000000000000000",
                "e33594d7505e43b90000000000000000" +
                "3394d7505e4379cd0100000000000000" +
                "00000000000000000000000000000000" +
                "01000000000000000000000000000000",
                "14000000000000005500000000000000",
            },
            // A.3 #11: 5*H+L reduction produces a 131-bit final result
            new[]
            {
                "01000000000000000400000000000000" + "00000000000000000000000000000000",
                "e33594d7505e43b90000000000000000" +
                "3394d7505e4379cd0100000000000000" +
                "00000000000000000000000000000000",
                "13000000000000000000000000000000",
            },
        };

        Span<byte> mac = stackalloc byte[16];
        foreach (string[] v in vectors)
        {
            byte[] key = Convert.FromHexString(v[0]);
            byte[] message = Convert.FromHexString(v[1]);
            byte[] tag = Convert.FromHexString(v[2]);
            Check.That(key.Length == 32 && tag.Length == 16);
            Aead.Poly1305Mac(mac, message, key);
            Check.That(mac.SequenceEqual(tag));
        }
    }

    public static void TestQueue()
    {
        var queue = new PacketQueue();

        Check.That(queue.Count == 0);

        // attempting to pop a packet off an empty queue should fail

        Span<byte> popped = stackalloc byte[Protocol.MaxPacketSize];
        Check.That(queue.Pop(popped, out _) == -1);

        // add some packets to the queue and make sure they pop off in the correct order

        var rng = new TestRng(0x1234);
        const int NumPackets = 100;
        byte[] payload = new byte[Protocol.MaxPacketSize];

        for (int i = 0; i < NumPackets; i++)
        {
            payload.AsSpan().Fill((byte)i);
            Check.That(queue.Push(payload.AsSpan(0, 1 + i * 3 % Protocol.MaxPacketSize), (ulong)i));
        }

        Check.That(queue.Count == NumPackets);

        for (int i = 0; i < NumPackets; i++)
        {
            int length = queue.Pop(popped, out ulong sequence);
            Check.That(sequence == (ulong)i);
            Check.That(length == 1 + i * 3 % Protocol.MaxPacketSize);
            for (int j = 0; j < length; j++)
                Check.That(popped[j] == (byte)i);
        }

        // after all entries are popped off, the queue is empty again

        Check.That(queue.Count == 0);
        Check.That(queue.Pop(popped, out _) == -1);

        // test that the packet queue can be filled to max capacity

        for (int i = 0; i < 256; i++)
        {
            payload.AsSpan().Fill((byte)i);
            Check.That(queue.Push(payload.AsSpan(0, 256), (ulong)i));
        }

        Check.That(queue.Count == 256);

        // when the queue is full, attempting to push a packet should fail

        Check.That(!queue.Push(payload.AsSpan(0, 100), 0));

        // make sure all packets pop off in the correct order

        for (int i = 0; i < 256; i++)
        {
            int length = queue.Pop(popped, out ulong sequence);
            Check.That(sequence == (ulong)i);
            Check.That(length == 256);
            for (int j = 0; j < length; j++)
                Check.That(popped[j] == (byte)i);
        }

        // add some packets again, clear, and the queue must be empty

        for (int i = 0; i < 256; i++)
            Check.That(queue.Push(payload.AsSpan(0, 64), (ulong)i));

        queue.Clear();

        Check.That(queue.Count == 0);
        Check.That(queue.Pop(popped, out _) == -1);

        _ = rng;
    }

    public static void TestSequence()
    {
        Check.That(PacketIO.SequenceNumberBytesRequired(0) == 1);
        Check.That(PacketIO.SequenceNumberBytesRequired(0x11) == 1);
        Check.That(PacketIO.SequenceNumberBytesRequired(0x1122) == 2);
        Check.That(PacketIO.SequenceNumberBytesRequired(0x112233) == 3);
        Check.That(PacketIO.SequenceNumberBytesRequired(0x11223344) == 4);
        Check.That(PacketIO.SequenceNumberBytesRequired(0x1122334455) == 5);
        Check.That(PacketIO.SequenceNumberBytesRequired(0x112233445566) == 6);
        Check.That(PacketIO.SequenceNumberBytesRequired(0x11223344556677) == 7);
        Check.That(PacketIO.SequenceNumberBytesRequired(0x1122334455667788) == 8);
    }

    public static void TestSocketBufferSizeBackOff()
    {
        const int requested = 4 * 1024 * 1024;

        // an OS that accepts the request (or clamps it, as linux and windows do) takes it on the first try

        {
            var tried = new System.Collections.Generic.List<int>();
            Check.That(NetcodeSocket.BufferSizeBackOff(requested, size => { tried.Add(size); return size <= requested; }) == requested);
            Check.That(tried.Count == 1);
        }

        // an OS that refuses anything over 227 KiB refuses 4M, 2M, 1M, 512K and 256K, and takes 128K

        {
            var tried = new System.Collections.Generic.List<int>();
            Check.That(NetcodeSocket.BufferSizeBackOff(requested, size => { tried.Add(size); return size <= 227 * 1024; }) == 128 * 1024);
            Check.That(string.Join(",", tried) == "4194304,2097152,1048576,524288,262144,131072");
        }

        // an OS that refuses every request down to the minimum keeps its default: not an error, and never a request below the minimum

        {
            var tried = new System.Collections.Generic.List<int>();
            Check.That(NetcodeSocket.BufferSizeBackOff(requested, size => { tried.Add(size); return false; }) == 0);
            Check.That(tried.Count == 7);
            Check.That(tried[tried.Count - 1] == NetcodeSocket.BufferSizeMinimum);
            Check.That(NetcodeSocket.BufferSizeMinimum == 64 * 1024);
        }

        // a request already below the minimum is not made at all

        {
            var tried = new System.Collections.Generic.List<int>();
            Check.That(NetcodeSocket.BufferSizeBackOff(32 * 1024, size => { tried.Add(size); return true; }) == 0);
            Check.That(tried.Count == 0);
        }
    }

    public static void TestAddress()
    {
        Check.That(!Address.TryParse("", out _));
        Check.That(!Address.TryParse("[", out _));
        Check.That(!Address.TryParse("[]", out _));
        Check.That(!Address.TryParse("[]:", out _));
        Check.That(!Address.TryParse(":", out _));
        Check.That(!Address.TryParse("1", out _));
        Check.That(!Address.TryParse("12", out _));
        Check.That(!Address.TryParse("123", out _));
        Check.That(!Address.TryParse("1234", out _));
        Check.That(!Address.TryParse("1234.0.12313.0000", out _));
        Check.That(!Address.TryParse("1234.0.12313.0000.0.0.0.0.0", out _));
        Check.That(!Address.TryParse("1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131", out _));
        Check.That(!Address.TryParse(".", out _));
        Check.That(!Address.TryParse("..", out _));
        Check.That(!Address.TryParse("...", out _));
        Check.That(!Address.TryParse("....", out _));
        Check.That(!Address.TryParse(".....", out _));

        // ports must be all digits in [0,65535]. out of range and non-numeric ports must not silently truncate

        {
            Check.That(Address.TryParse("127.0.0.1:65535", out Address address));
            Check.That(address.Type == AddressType.IPv4);
            Check.That(address.Port == 65535);
            Check.That(Address.TryParse("[::1]:65535", out address));
            Check.That(address.Type == AddressType.IPv6);
            Check.That(address.Port == 65535);
            Check.That(!Address.TryParse("127.0.0.1:65536", out _));
            Check.That(!Address.TryParse("127.0.0.1:99999", out _));
            Check.That(!Address.TryParse("127.0.0.1:", out _));
            Check.That(!Address.TryParse("127.0.0.1:40k", out _));
            Check.That(!Address.TryParse("[::1]:65536", out _));
            Check.That(!Address.TryParse("[::1]:", out _));
            Check.That(!Address.TryParse("[::1]:40k", out _));
        }

        // brackets and zone ids: at most one bracket pair is stripped, and any
        // bracket or zone marker left in the address part must be rejected

        {
            Check.That(!Address.TryParse("[[::1]]", out _));
            Check.That(!Address.TryParse("[::1]]:80", out _));
            Check.That(!Address.TryParse("[::1]:80]", out _));
            Check.That(!Address.TryParse("[::1]]", out _));
            Check.That(!Address.TryParse("fe80::1%eth0", out _));
            Check.That(!Address.TryParse("[fe80::1%eth0]", out _));
            Check.That(!Address.TryParse("[fe80::1%eth0]:80", out _));

            Check.That(Address.TryParse("127.0.0.1", out Address address));
            Check.That(address.Type == AddressType.IPv4 && address.Port == 0);
            Check.That(Address.TryParse("127.0.0.1:80", out address));
            Check.That(address.Type == AddressType.IPv4 && address.Port == 80);
            Check.That(Address.TryParse("::1", out address));
            Check.That(address.Type == AddressType.IPv6 && address.Port == 0);
            Check.That(Address.TryParse("[::1]", out address));
            Check.That(address.Type == AddressType.IPv6 && address.Port == 0);
            Check.That(Address.TryParse("[::1]:80", out address));
            Check.That(address.Type == AddressType.IPv6 && address.Port == 80);
            Check.That(Address.TryParse("fe80::1", out address));
            Check.That(address.Type == AddressType.IPv6 && address.Port == 0);
        }

        {
            Check.That(Address.TryParse("107.77.207.77", out Address address));
            Check.That(address.Type == AddressType.IPv4);
            Check.That(address.Port == 0);
            Check.That(address.GetIPv4(0) == 107 && address.GetIPv4(1) == 77 && address.GetIPv4(2) == 207 && address.GetIPv4(3) == 77);
        }

        {
            Check.That(Address.TryParse("127.0.0.1", out Address address));
            Check.That(address.Type == AddressType.IPv4);
            Check.That(address.Port == 0);
            Check.That(address.GetIPv4(0) == 127 && address.GetIPv4(1) == 0 && address.GetIPv4(2) == 0 && address.GetIPv4(3) == 1);
        }

        {
            Check.That(Address.TryParse("107.77.207.77:40000", out Address address));
            Check.That(address.Type == AddressType.IPv4);
            Check.That(address.Port == 40000);
            Check.That(address.GetIPv4(0) == 107 && address.GetIPv4(1) == 77 && address.GetIPv4(2) == 207 && address.GetIPv4(3) == 77);
        }

        {
            Check.That(Address.TryParse("fe80::202:b3ff:fe1e:8329", out Address address));
            Check.That(address.Type == AddressType.IPv6);
            Check.That(address.Port == 0);
            Check.That(address.GetIPv6(0) == 0xfe80);
            Check.That(address.GetIPv6(1) == 0x0000);
            Check.That(address.GetIPv6(2) == 0x0000);
            Check.That(address.GetIPv6(3) == 0x0000);
            Check.That(address.GetIPv6(4) == 0x0202);
            Check.That(address.GetIPv6(5) == 0xb3ff);
            Check.That(address.GetIPv6(6) == 0xfe1e);
            Check.That(address.GetIPv6(7) == 0x8329);
        }

        {
            Check.That(Address.TryParse("::", out Address address));
            Check.That(address.Type == AddressType.IPv6);
            Check.That(address.Port == 0);
            for (int i = 0; i < 8; i++)
                Check.That(address.GetIPv6(i) == 0);
        }

        {
            Check.That(Address.TryParse("::1", out Address address));
            Check.That(address.Type == AddressType.IPv6);
            Check.That(address.Port == 0);
            for (int i = 0; i < 7; i++)
                Check.That(address.GetIPv6(i) == 0);
            Check.That(address.GetIPv6(7) == 1);
        }

        {
            Check.That(Address.TryParse("::0", out Address address));
            Check.That(address.Type == AddressType.IPv6);
            for (int i = 0; i < 8; i++)
                Check.That(address.GetIPv6(i) == 0);
        }

        {
            Check.That(Address.TryParse("[::1]", out Address address));
            Check.That(address.Type == AddressType.IPv6);
            Check.That(address.Port == 0);
            Check.That(address.GetIPv6(7) == 1);
        }

        {
            Check.That(Address.TryParse("[::0]", out Address address));
            Check.That(address.Type == AddressType.IPv6);
            Check.That(address.Port == 0);
            Check.That(address.GetIPv6(7) == 0);
        }

        {
            Check.That(Address.TryParse("[fe80::1]", out Address address));
            Check.That(address.Type == AddressType.IPv6);
            Check.That(address.Port == 0);
            Check.That(address.GetIPv6(0) == 0xfe80 && address.GetIPv6(7) == 1);
        }

        {
            Check.That(Address.TryParse("[fe80::202:b3ff:fe1e:8329]:40000", out Address address));
            Check.That(address.Type == AddressType.IPv6);
            Check.That(address.Port == 40000);
            Check.That(address.GetIPv6(0) == 0xfe80);
            Check.That(address.GetIPv6(4) == 0x0202);
            Check.That(address.GetIPv6(5) == 0xb3ff);
            Check.That(address.GetIPv6(6) == 0xfe1e);
            Check.That(address.GetIPv6(7) == 0x8329);
        }

        {
            Check.That(Address.TryParse("[::]:40000", out Address address));
            Check.That(address.Type == AddressType.IPv6);
            Check.That(address.Port == 40000);
            for (int i = 0; i < 8; i++)
                Check.That(address.GetIPv6(i) == 0);
        }

        {
            Check.That(Address.TryParse("[::1]:5", out Address address));
            Check.That(address.Type == AddressType.IPv6);
            Check.That(address.Port == 5);
            Check.That(address.GetIPv6(7) == 1);
        }

        {
            Check.That(Address.TryParse("[fe80::1]:5", out Address address));
            Check.That(address.Type == AddressType.IPv6);
            Check.That(address.Port == 5);
            Check.That(address.GetIPv6(0) == 0xfe80 && address.GetIPv6(7) == 1);
        }

        {
            Check.That(Address.TryParse("[::1]:40000", out Address address));
            Check.That(address.Type == AddressType.IPv6);
            Check.That(address.Port == 40000);
            Check.That(address.GetIPv6(7) == 1);
        }

        // to-string round trips (C# addition: the C library formats the same way)

        Check.That(Address.Parse("107.77.207.77:40000").ToString() == "107.77.207.77:40000");
        Check.That(Address.Parse("127.0.0.1").ToString() == "127.0.0.1");
        Check.That(Address.Parse("[fe80::202:b3ff:fe1e:8329]:40000").ToString() == "[fe80::202:b3ff:fe1e:8329]:40000");
        Check.That(Address.Parse("::1").ToString() == "::1");
        Check.That(default(Address).ToString() == "NONE");
    }

    private static Address TestServerAddress()
    {
        Address address = default;
        address.SetIPv4(127, 0, 0, 1);
        address.Port = TestConstants.TestServerPort;
        return address;
    }

    public static void TestConnectToken()
    {
        // generate a connect token

        Address serverAddress = TestServerAddress();

        byte[] userData = new byte[Protocol.UserDataBytes];
        new TestRng(0xAA55).Fill(userData);

        var inputToken = new ConnectTokenPrivate();
        Span<Address> addresses = stackalloc Address[1] { serverAddress };
        inputToken.Generate(TestConstants.TestClientId, TestConstants.TestTimeoutSeconds, addresses, userData);

        Check.That(inputToken.ClientId == TestConstants.TestClientId);
        Check.That(inputToken.NumServerAddresses == 1);
        Check.That(inputToken.UserData.AsSpan().SequenceEqual(userData));
        Check.That(inputToken.ServerAddresses[0].Equals(serverAddress));

        // write it to a buffer

        byte[] buffer = new byte[Defines.ConnectTokenPrivateBytes];
        inputToken.Write(buffer);

        // encrypt the buffer

        ulong expireTimestamp = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 30;
        byte[] nonce = new byte[Defines.ConnectTokenNonceBytes];
        Rng.GenerateNonce(nonce);
        byte[] key = new byte[Protocol.KeyBytes];
        Rng.GenerateKey(key);

        Check.That(ConnectTokenPrivate.Encrypt(buffer, Defines.VersionInfo, TestConstants.TestProtocolId, expireTimestamp, nonce, key));

        // decrypt the buffer

        Check.That(ConnectTokenPrivate.Decrypt(buffer, Defines.VersionInfo, TestConstants.TestProtocolId, expireTimestamp, nonce, key));

        // read the connect token back in and verify everything matches

        var outputToken = new ConnectTokenPrivate();
        Check.That(outputToken.Read(buffer));

        Check.That(outputToken.ClientId == inputToken.ClientId);
        Check.That(outputToken.TimeoutSeconds == inputToken.TimeoutSeconds);
        Check.That(outputToken.NumServerAddresses == inputToken.NumServerAddresses);
        Check.That(outputToken.ServerAddresses[0].Equals(inputToken.ServerAddresses[0]));
        Check.That(outputToken.ClientToServerKey.AsSpan().SequenceEqual(inputToken.ClientToServerKey));
        Check.That(outputToken.ServerToClientKey.AsSpan().SequenceEqual(inputToken.ServerToClientKey));
        Check.That(outputToken.UserData.AsSpan().SequenceEqual(inputToken.UserData));
    }

    public static void TestGenerateConnectTokenOutOfRange()
    {
        // netcode_generate_connect_token guards num_server_addresses with a runtime
        // check (upstream fix; the parse arrays are sized MaxServersPerConnect).
        // In C# the equivalent guard must reject empty and oversized address lists.

        byte[] connectToken = new byte[Protocol.ConnectTokenBytes];
        byte[] userData = new byte[Protocol.UserDataBytes];

        string[] none = Array.Empty<string>();
        Check.That(!ConnectTokenGenerator.Generate(none, none, 30, 5, 1000UL, TestConstants.TestProtocolId, TestConstants.PrivateKey, userData, connectToken));

        string[] tooMany = new string[Protocol.MaxServersPerConnect + 1];
        Array.Fill(tooMany, "127.0.0.1:40000");
        Check.That(!ConnectTokenGenerator.Generate(tooMany, tooMany, 30, 5, 1000UL, TestConstants.TestProtocolId, TestConstants.PrivateKey, userData, connectToken));

        // and an in-range call still succeeds, so the guard cannot pass by rejecting everything

        string[] one = { "127.0.0.1:40000" };
        Check.That(ConnectTokenGenerator.Generate(one, one, 30, 5, 1000UL, TestConstants.TestProtocolId, TestConstants.PrivateKey, userData, connectToken));
    }

    public static void TestChallengeToken()
    {
        // generate a challenge token

        var inputToken = new ChallengeToken();
        inputToken.ClientId = TestConstants.TestClientId;
        new TestRng(0x77).Fill(inputToken.UserData);

        // write it to a buffer

        byte[] buffer = new byte[Defines.ChallengeTokenBytes];
        inputToken.Write(buffer);

        // encrypt the buffer

        ulong sequence = 1000;
        byte[] key = new byte[Protocol.KeyBytes];
        Rng.GenerateKey(key);

        ChallengeToken.Encrypt(buffer, sequence, key);

        // decrypt the buffer

        Check.That(ChallengeToken.Decrypt(buffer, sequence, key));

        // read the challenge token back in and verify everything matches

        var outputToken = new ChallengeToken();
        Check.That(outputToken.Read(buffer));

        Check.That(outputToken.ClientId == inputToken.ClientId);
        Check.That(outputToken.UserData.AsSpan().SequenceEqual(inputToken.UserData));
    }

    private static readonly bool[] AllAllowed = CreateAllAllowed();

    private static bool[] CreateAllAllowed()
    {
        var allowed = new bool[PacketType.NumPackets];
        Array.Fill(allowed, true);
        return allowed;
    }

    public static void TestConnectionRequestPacket()
    {
        // generate a private connect token and write it (non-encrypted copy kept for verification)

        Address serverAddress = TestServerAddress();

        byte[] userData = new byte[Protocol.UserDataBytes];
        new TestRng(0x99).Fill(userData);

        var inputToken = new ConnectTokenPrivate();
        Span<Address> addresses = stackalloc Address[1] { serverAddress };
        inputToken.Generate(TestConstants.TestClientId, TestConstants.TestTimeoutSeconds, addresses, userData);

        byte[] connectTokenData = new byte[Defines.ConnectTokenPrivateBytes];
        inputToken.Write(connectTokenData);

        byte[] encryptedConnectTokenData = (byte[])connectTokenData.Clone();

        ulong expireTimestamp = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 30;
        byte[] nonce = new byte[Defines.ConnectTokenNonceBytes];
        Rng.GenerateNonce(nonce);
        byte[] key = new byte[Protocol.KeyBytes];
        Rng.GenerateKey(key);

        Check.That(ConnectTokenPrivate.Encrypt(encryptedConnectTokenData, Defines.VersionInfo, TestConstants.TestProtocolId, expireTimestamp, nonce, key));

        // write a connection request packet wrapping the encrypted connect token

        byte[] buffer = new byte[2048];
        int bytesWritten = PacketIO.WriteConnectionRequestPacket(buffer, Defines.VersionInfo, TestConstants.TestProtocolId, expireTimestamp, nonce, encryptedConnectTokenData);

        Check.That(bytesWritten == PacketIO.ConnectionRequestPacketBytes);

        // read the packet back in (the connect token data is decrypted as part of the read)

        ReadPacketResult result = PacketIO.ReadPacket(
            buffer.AsSpan(0, bytesWritten),
            hasReadPacketKey: true, new byte[Protocol.KeyBytes],
            TestConstants.TestProtocolId,
            (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            hasPrivateKey: true, key,
            AllAllowed, null);

        Check.That(result.Type == PacketType.ConnectionRequest);
        Check.That(result.DataLength == Defines.ConnectTokenPrivateBytes);
        Check.That(buffer.AsSpan(result.DataOffset, Defines.ConnectTokenPrivateBytes - Protocol.MacBytes)
            .SequenceEqual(connectTokenData.AsSpan(0, Defines.ConnectTokenPrivateBytes - Protocol.MacBytes)));

        var outputToken = new ConnectTokenPrivate();
        Check.That(outputToken.Read(buffer.AsSpan(result.DataOffset, result.DataLength)));
        Check.That(outputToken.ClientId == TestConstants.TestClientId);
    }

    public static void TestEmptyPacket(int packetType)
    {
        // denied and disconnect packets: no data, encrypted

        byte[] buffer = new byte[Defines.MaxPacketBytes];
        byte[] packetKey = new byte[Protocol.KeyBytes];
        Rng.GenerateKey(packetKey);

        int bytesWritten = PacketIO.WriteEncryptedPacket(buffer, packetType, ReadOnlySpan<byte>.Empty, 1000, packetKey, TestConstants.TestProtocolId);
        Check.That(bytesWritten > 0);

        ReadPacketResult result = PacketIO.ReadPacket(
            buffer.AsSpan(0, bytesWritten),
            hasReadPacketKey: true, packetKey,
            TestConstants.TestProtocolId,
            (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            hasPrivateKey: false, ReadOnlySpan<byte>.Empty,
            AllAllowed, null);

        Check.That(result.Type == packetType);
        Check.That(result.Sequence == 1000);
        Check.That(result.DataLength == 0);
    }

    public static void TestChallengeResponsePacket(int packetType)
    {
        // challenge and response packets: challenge token sequence + 300 bytes of token data

        byte[] packetData = new byte[8 + Defines.ChallengeTokenBytes];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(packetData.AsSpan(0, 8), 0);
        new TestRng(0x1EE7).Fill(packetData.AsSpan(8));

        byte[] buffer = new byte[Defines.MaxPacketBytes];
        byte[] packetKey = new byte[Protocol.KeyBytes];
        Rng.GenerateKey(packetKey);

        int bytesWritten = PacketIO.WriteEncryptedPacket(buffer, packetType, packetData, 1000, packetKey, TestConstants.TestProtocolId);
        Check.That(bytesWritten > 0);

        ReadPacketResult result = PacketIO.ReadPacket(
            buffer.AsSpan(0, bytesWritten),
            hasReadPacketKey: true, packetKey,
            TestConstants.TestProtocolId,
            (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            hasPrivateKey: false, ReadOnlySpan<byte>.Empty,
            AllAllowed, null);

        Check.That(result.Type == packetType);
        Check.That(result.Sequence == 1000);
        Check.That(result.DataLength == 8 + Defines.ChallengeTokenBytes);
        Check.That(buffer.AsSpan(result.DataOffset, result.DataLength).SequenceEqual(packetData));
    }

    public static void TestConnectionKeepAlivePacket()
    {
        byte[] packetData = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(packetData.AsSpan(0, 4), 10); // client index
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(packetData.AsSpan(4, 4), 16); // max clients

        byte[] buffer = new byte[Defines.MaxPacketBytes];
        byte[] packetKey = new byte[Protocol.KeyBytes];
        Rng.GenerateKey(packetKey);

        int bytesWritten = PacketIO.WriteEncryptedPacket(buffer, PacketType.ConnectionKeepAlive, packetData, 1000, packetKey, TestConstants.TestProtocolId);
        Check.That(bytesWritten > 0);

        ReadPacketResult result = PacketIO.ReadPacket(
            buffer.AsSpan(0, bytesWritten),
            hasReadPacketKey: true, packetKey,
            TestConstants.TestProtocolId,
            (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            hasPrivateKey: false, ReadOnlySpan<byte>.Empty,
            AllAllowed, null);

        Check.That(result.Type == PacketType.ConnectionKeepAlive);
        Check.That(result.DataLength == 8);
        Check.That(buffer.AsSpan(result.DataOffset, 8).SequenceEqual(packetData));
    }

    public static void TestConnectionPayloadPacket()
    {
        byte[] payload = new byte[Defines.MaxPayloadBytes];
        new TestRng(0xF00D).Fill(payload);

        byte[] buffer = new byte[Defines.MaxPacketBytes];
        byte[] packetKey = new byte[Protocol.KeyBytes];
        Rng.GenerateKey(packetKey);

        int bytesWritten = PacketIO.WriteEncryptedPacket(buffer, PacketType.ConnectionPayload, payload, 1000, packetKey, TestConstants.TestProtocolId);
        Check.That(bytesWritten > 0);

        ReadPacketResult result = PacketIO.ReadPacket(
            buffer.AsSpan(0, bytesWritten),
            hasReadPacketKey: true, packetKey,
            TestConstants.TestProtocolId,
            (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            hasPrivateKey: false, ReadOnlySpan<byte>.Empty,
            AllAllowed, null);

        Check.That(result.Type == PacketType.ConnectionPayload);
        Check.That(result.DataLength == Defines.MaxPayloadBytes);
        Check.That(buffer.AsSpan(result.DataOffset, result.DataLength).SequenceEqual(payload));
    }

    public static void TestConnectTokenPublic()
    {
        // generate a private connect token, encrypt it, wrap a public connect token around it

        Address serverAddress = TestServerAddress();

        byte[] userData = new byte[Protocol.UserDataBytes];
        new TestRng(0xABCD).Fill(userData);

        var connectTokenPrivate = new ConnectTokenPrivate();
        Span<Address> addresses = stackalloc Address[1] { serverAddress };
        connectTokenPrivate.Generate(TestConstants.TestClientId, TestConstants.TestTimeoutSeconds, addresses, userData);

        byte[] connectTokenPrivateData = new byte[Defines.ConnectTokenPrivateBytes];
        connectTokenPrivate.Write(connectTokenPrivateData);

        ulong createTimestamp = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        ulong expireTimestamp = createTimestamp + 30;
        byte[] nonce = new byte[Defines.ConnectTokenNonceBytes];
        Rng.GenerateNonce(nonce);
        byte[] key = new byte[Protocol.KeyBytes];
        Rng.GenerateKey(key);
        Check.That(ConnectTokenPrivate.Encrypt(connectTokenPrivateData, Defines.VersionInfo, TestConstants.TestProtocolId, expireTimestamp, nonce, key));

        var inputConnectToken = new ConnectTokenData();
        Defines.VersionInfo.CopyTo(inputConnectToken.VersionInfo);
        inputConnectToken.ProtocolId = TestConstants.TestProtocolId;
        inputConnectToken.CreateTimestamp = createTimestamp;
        inputConnectToken.ExpireTimestamp = expireTimestamp;
        nonce.CopyTo(inputConnectToken.Nonce, 0);
        connectTokenPrivateData.CopyTo(inputConnectToken.PrivateData, 0);
        inputConnectToken.NumServerAddresses = 1;
        inputConnectToken.ServerAddresses[0] = serverAddress;
        connectTokenPrivate.ClientToServerKey.CopyTo(inputConnectToken.ClientToServerKey, 0);
        connectTokenPrivate.ServerToClientKey.CopyTo(inputConnectToken.ServerToClientKey, 0);
        inputConnectToken.TimeoutSeconds = TestConstants.TestTimeoutSeconds;

        // write the connect token to a buffer, read it back in, verify it matches

        byte[] buffer = new byte[Protocol.ConnectTokenBytes];
        inputConnectToken.Write(buffer);

        var outputConnectToken = new ConnectTokenData();
        Check.That(outputConnectToken.Read(buffer));

        Check.That(outputConnectToken.VersionInfo.AsSpan().SequenceEqual(inputConnectToken.VersionInfo));
        Check.That(outputConnectToken.ProtocolId == inputConnectToken.ProtocolId);
        Check.That(outputConnectToken.CreateTimestamp == inputConnectToken.CreateTimestamp);
        Check.That(outputConnectToken.ExpireTimestamp == inputConnectToken.ExpireTimestamp);
        Check.That(outputConnectToken.Nonce.AsSpan().SequenceEqual(inputConnectToken.Nonce));
        Check.That(outputConnectToken.PrivateData.AsSpan().SequenceEqual(inputConnectToken.PrivateData));
        Check.That(outputConnectToken.NumServerAddresses == inputConnectToken.NumServerAddresses);
        Check.That(outputConnectToken.ServerAddresses[0].Equals(inputConnectToken.ServerAddresses[0]));
        Check.That(outputConnectToken.ClientToServerKey.AsSpan().SequenceEqual(inputConnectToken.ClientToServerKey));
        Check.That(outputConnectToken.ServerToClientKey.AsSpan().SequenceEqual(inputConnectToken.ServerToClientKey));
        Check.That(outputConnectToken.TimeoutSeconds == inputConnectToken.TimeoutSeconds);
    }

    private delegate void ProcessAtTime(in Address from, Span<byte> packet, ulong timestamp);

    public static void TestKeyCleanup()
    {
        const System.Reflection.BindingFlags Fields = System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic;
        var key = (byte[])TestConstants.PrivateKey.Clone();
        var config = new ServerConfig
        {
            ProtocolId = TestConstants.TestProtocolId,
            PrivateKey = key,
            OverrideSendAndReceive = true,
            SendPacketOverride = (in Address to, ReadOnlySpan<byte> packet) => { },
            ReceivePacketOverride = (ref Address from, Span<byte> packet) => 0,
        };
        using var server = new Server("127.0.0.1:40000", config, 1000);
        var ownedKey = (byte[])typeof(Server).GetField("_privateKey", Fields)!.GetValue(server)!;
        Check.That(ownedKey.AsSpan().SequenceEqual(key));
        typeof(Server).GetField("_running", Fields)!.SetValue(server, true);
        var process = typeof(Server).GetMethod("ReadAndProcessPacket", Fields)!.CreateDelegate<ProcessAtTime>(server);
        Address.TryParse("127.0.0.1:40000", out Address serverAddress);
        Address.TryParse("127.0.0.1:50000", out Address clientAddress);
        foreach (int mode in new[] { 0, 1, 2 })
        {
            server.Flags = mode == 2 ? Server.FlagIgnoreConnectionRequestPackets : 0;
            var token = new ConnectTokenPrivate();
            token.Generate(1, 15, new[] { mode != 1 ? serverAddress : clientAddress }, new byte[Protocol.UserDataBytes]);
            byte[] privateData = new byte[Defines.ConnectTokenPrivateBytes];
            token.Write(privateData);
            byte[] nonce = new byte[Defines.ConnectTokenNonceBytes];
            Check.That(ConnectTokenPrivate.Encrypt(privateData, Defines.VersionInfo, config.ProtocolId, 1030, nonce, key));
            byte[] packet = new byte[PacketIO.ConnectionRequestPacketBytes];
            Check.That(PacketIO.WriteConnectionRequestPacket(packet, Defines.VersionInfo, config.ProtocolId, 1030, nonce, privateData) == packet.Length);
            process(in clientAddress, packet, 1000);
            Check.That(packet.AsSpan(packet.Length - Defines.ConnectTokenPrivateBytes).IndexOfAnyExcept((byte)0) == -1);
        }
        server.Dispose();
        Check.That(ownedKey.AsSpan().IndexOfAnyExcept((byte)0) == -1);
        Check.That(key.AsSpan().SequenceEqual(TestConstants.PrivateKey));

        var ownedManager = new EncryptionManager();
        Check.That(ownedManager.AddEncryptionMapping(in serverAddress, key, key, 1000, 1001, 15));
        ownedManager.SetExpireTime(0, -1);
        ownedManager.ClientIndex[0] = 0;
        Check.That(ownedManager.AddEncryptionMapping(in clientAddress, key, key, 1030, -1, 15));
        Check.That(ownedManager.SendKey.AsSpan(0, Protocol.KeyBytes).SequenceEqual(key));
        Check.That(ownedManager.ReceiveKey.AsSpan(0, Protocol.KeyBytes).SequenceEqual(key));
        Check.That(ownedManager.RemoveEncryptionMapping(in clientAddress, 1030));
        Check.That(ownedManager.SendKey.AsSpan(0, Protocol.KeyBytes).SequenceEqual(key));
        Check.That(ownedManager.ReceiveKey.AsSpan(0, Protocol.KeyBytes).SequenceEqual(key));
        Check.That(ownedManager.Touch(0, in serverAddress, 1030));
        Check.That(ownedManager.FindEncryptionMapping(in serverAddress, 1030) == 0);
        Check.That(ownedManager.GetSendKey(0).SequenceEqual(key));
        Check.That(ownedManager.GetReceiveKey(0).SequenceEqual(key));

        var manager = new EncryptionManager();
        Check.That(manager.AddEncryptionMapping(in serverAddress, key, key, 1000, 1001, 15));
        Check.That(manager.AddEncryptionMapping(in clientAddress, key, key, 1000, -1, 15));
        Check.That(manager.RemoveEncryptionMapping(in clientAddress, 1002));
        Check.That(manager.SendKey.AsSpan(0, 2 * Protocol.KeyBytes).IndexOfAnyExcept((byte)0) == -1);
        Check.That(manager.ReceiveKey.AsSpan(0, 2 * Protocol.KeyBytes).IndexOfAnyExcept((byte)0) == -1);
        Check.That(manager.AddEncryptionMapping(in serverAddress, key, key, 1000, 1001, 15));
        Check.That(manager.FindEncryptionMapping(in serverAddress, 1002) == -1);
        Check.That(manager.SendKey.AsSpan(0, Protocol.KeyBytes).IndexOfAnyExcept((byte)0) == -1);
        Check.That(manager.ReceiveKey.AsSpan(0, Protocol.KeyBytes).IndexOfAnyExcept((byte)0) == -1);
    }

    public static void TestEncryptionManager()
    {
        var encryptionManager = new EncryptionManager();

        double time = 100.0;

        // generate some test encryption mappings

        const int NumEncryptionMappings = 5;

        var addresses = new Address[NumEncryptionMappings];
        var sendKeys = new byte[NumEncryptionMappings][];
        var receiveKeys = new byte[NumEncryptionMappings][];

        for (int i = 0; i < NumEncryptionMappings; i++)
        {
            addresses[i] = default;
            addresses[i].SetIPv6(0, 0, 0, 0, 0, 0, 0, 1);
            addresses[i].Port = (ushort)(20000 + i);
            sendKeys[i] = new byte[Protocol.KeyBytes];
            receiveKeys[i] = new byte[Protocol.KeyBytes];
            Rng.GenerateKey(sendKeys[i]);
            Rng.GenerateKey(receiveKeys[i]);
        }

        // add the encryption mappings and look them up by address

        for (int i = 0; i < NumEncryptionMappings; i++)
        {
            int encryptionIndex = encryptionManager.FindEncryptionMapping(in addresses[i], time);
            Check.That(encryptionIndex == -1);
            Check.That(encryptionManager.GetSendKey(encryptionIndex).Length == 0);
            Check.That(encryptionManager.GetReceiveKey(encryptionIndex).Length == 0);

            Check.That(encryptionManager.AddEncryptionMapping(in addresses[i], sendKeys[i], receiveKeys[i], time, -1.0, TestConstants.TestTimeoutSeconds));

            encryptionIndex = encryptionManager.FindEncryptionMapping(in addresses[i], time);
            Check.That(encryptionManager.GetSendKey(encryptionIndex).SequenceEqual(sendKeys[i]));
            Check.That(encryptionManager.GetReceiveKey(encryptionIndex).SequenceEqual(receiveKeys[i]));
        }

        // removing an encryption mapping that doesn't exist should fail

        {
            Address address = default;
            address.SetIPv6(0, 0, 0, 0, 0, 0, 0, 1);
            address.Port = 50000;
            Check.That(!encryptionManager.RemoveEncryptionMapping(in address, time));
        }

        // remove the first and last encryption mappings

        Check.That(encryptionManager.RemoveEncryptionMapping(in addresses[0], time));
        Check.That(encryptionManager.RemoveEncryptionMapping(in addresses[NumEncryptionMappings - 1], time));

        // make sure the removed mappings can no longer be looked up

        for (int i = 0; i < NumEncryptionMappings; i++)
        {
            int encryptionIndex = encryptionManager.FindEncryptionMapping(in addresses[i], time);

            if (i != 0 && i != NumEncryptionMappings - 1)
            {
                Check.That(encryptionManager.GetSendKey(encryptionIndex).SequenceEqual(sendKeys[i]));
                Check.That(encryptionManager.GetReceiveKey(encryptionIndex).SequenceEqual(receiveKeys[i]));
            }
            else
            {
                Check.That(encryptionManager.GetSendKey(encryptionIndex).Length == 0);
                Check.That(encryptionManager.GetReceiveKey(encryptionIndex).Length == 0);
            }
        }

        // add the mappings back in; all should be findable again

        Check.That(encryptionManager.AddEncryptionMapping(in addresses[0], sendKeys[0], receiveKeys[0], time, -1.0, TestConstants.TestTimeoutSeconds));
        Check.That(encryptionManager.AddEncryptionMapping(in addresses[NumEncryptionMappings - 1], sendKeys[NumEncryptionMappings - 1], receiveKeys[NumEncryptionMappings - 1], time, -1.0, TestConstants.TestTimeoutSeconds));

        for (int i = 0; i < NumEncryptionMappings; i++)
        {
            int encryptionIndex = encryptionManager.FindEncryptionMapping(in addresses[i], time);
            Check.That(encryptionManager.GetSendKey(encryptionIndex).SequenceEqual(sendKeys[i]));
            Check.That(encryptionManager.GetReceiveKey(encryptionIndex).SequenceEqual(receiveKeys[i]));
        }

        // check that encryption mappings time out properly

        time += TestConstants.TestTimeoutSeconds * 2;

        for (int i = 0; i < NumEncryptionMappings; i++)
        {
            int encryptionIndex = encryptionManager.FindEncryptionMapping(in addresses[i], time);
            Check.That(encryptionManager.GetSendKey(encryptionIndex).Length == 0);
            Check.That(encryptionManager.GetReceiveKey(encryptionIndex).Length == 0);
        }

        // add the same encryption mappings after timeout

        for (int i = 0; i < NumEncryptionMappings; i++)
        {
            int encryptionIndex = encryptionManager.FindEncryptionMapping(in addresses[i], time);
            Check.That(encryptionIndex == -1);

            Check.That(encryptionManager.AddEncryptionMapping(in addresses[i], sendKeys[i], receiveKeys[i], time, -1.0, TestConstants.TestTimeoutSeconds));

            encryptionIndex = encryptionManager.FindEncryptionMapping(in addresses[i], time);
            Check.That(encryptionManager.GetSendKey(encryptionIndex).SequenceEqual(sendKeys[i]));
            Check.That(encryptionManager.GetReceiveKey(encryptionIndex).SequenceEqual(receiveKeys[i]));
        }

        // reset the encryption manager and verify all mappings are removed

        encryptionManager.Reset();

        for (int i = 0; i < NumEncryptionMappings; i++)
        {
            int encryptionIndex = encryptionManager.FindEncryptionMapping(in addresses[i], time);
            Check.That(encryptionIndex == -1);
        }

        // test the expire time for encryption mappings works as expected

        Check.That(encryptionManager.AddEncryptionMapping(in addresses[0], sendKeys[0], receiveKeys[0], time, time + 1.0, TestConstants.TestTimeoutSeconds));

        int index = encryptionManager.FindEncryptionMapping(in addresses[0], time);
        Check.That(index != -1);

        Check.That(encryptionManager.FindEncryptionMapping(in addresses[0], time + 1.1) == -1);

        encryptionManager.SetExpireTime(index, -1.0);

        Check.That(encryptionManager.FindEncryptionMapping(in addresses[0], time) == index);
    }

    public static void TestReplayProtection()
    {
        var replayProtection = new ReplayProtection();

        for (int i = 0; i < 2; i++)
        {
            replayProtection.Reset();

            Check.That(replayProtection.MostRecentSequence == 0);

            // the first time we receive packets, they should not be already received

            const ulong MaxSequence = Defines.ReplayProtectionBufferSize * 4;

            for (ulong sequence = 0; sequence < MaxSequence; sequence++)
            {
                Check.That(!replayProtection.AlreadyReceived(sequence));
                replayProtection.AdvanceSequence(sequence);
            }

            // old packets outside the buffer should be considered already received

            Check.That(replayProtection.AlreadyReceived(0));

            // packets received a second time should be flagged already received

            for (ulong sequence = MaxSequence - 10; sequence < MaxSequence; sequence++)
                Check.That(replayProtection.AlreadyReceived(sequence));

            // jumping ahead to a much higher sequence should be considered not already received

            Check.That(!replayProtection.AlreadyReceived(MaxSequence + Defines.ReplayProtectionBufferSize));

            // old packets should be considered already received

            for (ulong sequence = 0; sequence < MaxSequence; sequence++)
                Check.That(replayProtection.AlreadyReceived(sequence));
        }

        // sequence numbers near UINT64_MAX must not be falsely rejected as replays
        // ("sequence + buffer size" overflowed in the C library once; found by fuzzing)

        replayProtection.Reset();

        Check.That(!replayProtection.AlreadyReceived(ulong.MaxValue - Defines.ReplayProtectionBufferSize));
        replayProtection.AdvanceSequence(ulong.MaxValue - Defines.ReplayProtectionBufferSize);

        Check.That(!replayProtection.AlreadyReceived(ulong.MaxValue - 1));
        replayProtection.AdvanceSequence(ulong.MaxValue - 1);

        // and a replayed packet up there is still caught

        Check.That(replayProtection.AlreadyReceived(ulong.MaxValue - 1));

        // while packets that fell out of the window are rejected as before

        Check.That(replayProtection.AlreadyReceived(ulong.MaxValue - 1 - Defines.ReplayProtectionBufferSize));

        // the empty-slot sentinel value ulong.MaxValue is reserved and rejected

        Check.That(replayProtection.AlreadyReceived(ulong.MaxValue));

        replayProtection.Reset();

        for (ulong sequence = 1; sequence <= 4; sequence++)
        {
            Check.That(!replayProtection.AlreadyReceived(sequence));
            replayProtection.AdvanceSequence(sequence);
        }

        Check.That(replayProtection.AlreadyReceived(ulong.MaxValue));
        replayProtection.AdvanceSequence(ulong.MaxValue);
        Check.That(replayProtection.MostRecentSequence == 4);
        Check.That(!replayProtection.AlreadyReceived(5));

        byte[] packetData = new byte[8];
        byte[] buffer = new byte[Defines.MaxPacketBytes];
        byte[] packetKey = new byte[Protocol.KeyBytes];
        Rng.GenerateKey(packetKey);

        int sentinelBytes = PacketIO.WriteEncryptedPacket(buffer, PacketType.ConnectionKeepAlive, packetData, ulong.MaxValue, packetKey, TestConstants.TestProtocolId);
        Check.That(sentinelBytes > 0);

        ReadPacketResult sentinelResult = PacketIO.ReadPacket(
            buffer.AsSpan(0, sentinelBytes),
            hasReadPacketKey: true, packetKey,
            TestConstants.TestProtocolId,
            0,
            hasPrivateKey: false, ReadOnlySpan<byte>.Empty,
            AllAllowed, replayProtection);
        Check.That(sentinelResult.Type == -1);

        ReadPacketResult sentinelNoReplayResult = PacketIO.ReadPacket(
            buffer.AsSpan(0, sentinelBytes),
            hasReadPacketKey: true, packetKey,
            TestConstants.TestProtocolId,
            0,
            hasPrivateKey: false, ReadOnlySpan<byte>.Empty,
            AllAllowed, null);
        Check.That(sentinelNoReplayResult.Type == -1);

        int nextBytes = PacketIO.WriteEncryptedPacket(buffer, PacketType.ConnectionKeepAlive, packetData, 5, packetKey, TestConstants.TestProtocolId);
        Check.That(nextBytes > 0);

        ReadPacketResult nextResult = PacketIO.ReadPacket(
            buffer.AsSpan(0, nextBytes),
            hasReadPacketKey: true, packetKey,
            TestConstants.TestProtocolId,
            0,
            hasPrivateKey: false, ReadOnlySpan<byte>.Empty,
            AllAllowed, replayProtection);
        Check.That(nextResult.Type == PacketType.ConnectionKeepAlive);
        Check.That(nextResult.Sequence == 5);
    }

    public static void TestNetworkSimulatorDeterminism()
    {
        // two simulators given identical inputs must drop, delay and duplicate identically

        const int NumPackets = 100;

        var simulatorA = new NetworkSimulator { LatencyMilliseconds = 100.0f, JitterMilliseconds = 50.0f, PacketLossPercent = 25.0f, DuplicatePacketPercent = 25.0f };
        var simulatorB = new NetworkSimulator { LatencyMilliseconds = 100.0f, JitterMilliseconds = 50.0f, PacketLossPercent = 25.0f, DuplicatePacketPercent = 25.0f };

        Address from = Address.Parse("127.0.0.1:40000");
        Address to = Address.Parse("127.0.0.1:50000");

        byte[] packetData = new byte[256];
        for (int i = 0; i < NumPackets; i++)
        {
            for (int j = 0; j < packetData.Length; j++)
                packetData[j] = (byte)(i + j);
            simulatorA.SendPacket(in from, in to, packetData);
            simulatorB.SendPacket(in from, in to, packetData);
        }

        int totalReceived = 0;

        var receivedA = new System.Collections.Generic.List<byte[]>();
        var receivedB = new System.Collections.Generic.List<byte[]>();

        for (double time = 0.0; time < 2.0; time += 0.01)
        {
            simulatorA.Update(time);
            simulatorB.Update(time);

            receivedA.Clear();
            receivedB.Clear();

            simulatorA.ReceivePackets(in to, 256, (in Address _, ReadOnlySpan<byte> data) => receivedA.Add(data.ToArray()));
            simulatorB.ReceivePackets(in to, 256, (in Address _, ReadOnlySpan<byte> data) => receivedB.Add(data.ToArray()));

            Check.That(receivedA.Count == receivedB.Count);

            for (int i = 0; i < receivedA.Count; i++)
                Check.That(receivedA[i].AsSpan().SequenceEqual(receivedB[i]));

            totalReceived += receivedA.Count;
        }

        Check.That(totalReceived > 0);
    }
}

internal static class ReceiveBufferTests
{
    public static void TestReceivePacketShortBuffer()
    {
        byte[] queued = new byte[500];
        for (int i = 0; i < queued.Length; i++)
            queued[i] = (byte)(i % 251);

        byte[] shortBuffer = new byte[Protocol.MaxPacketSize - 1];
        byte[] fullBuffer = new byte[Protocol.MaxPacketSize];

        var clientConfig = new ClientConfig
        {
            OverrideSendAndReceive = true,
            SendPacketOverride = (in Address to, ReadOnlySpan<byte> payload) => { },
            ReceivePacketOverride = (ref Address from, Span<byte> payload) => 0,
            SendLoopbackPacket = (int clientIndex, ReadOnlySpan<byte> payload, ulong sequence) => { },
        };
        using var client = new Client("127.0.0.1:40000", clientConfig, 1000.0);
        client.ConnectLoopback(0, 1);
        Check.That(client.State == ClientState.Connected);
        client.ProcessLoopbackPacket(queued, 42);

        ArgumentException? clientError = null;
        try
        {
            client.ReceivePacket(shortBuffer, out _);
        }
        catch (ArgumentException e)
        {
            clientError = e;
        }
        Check.That(clientError != null);
        Check.That(clientError!.ParamName == "payload");

        int clientLength = client.ReceivePacket(fullBuffer, out ulong clientSequence);
        Check.That(clientLength == queued.Length);
        Check.That(clientSequence == 42UL);
        Check.That(fullBuffer.AsSpan(0, clientLength).SequenceEqual(queued));

        bool clientThrewWhenEmpty = false;
        try
        {
            client.ReceivePacket(shortBuffer, out _);
        }
        catch (ArgumentException)
        {
            clientThrewWhenEmpty = true;
        }
        Check.That(clientThrewWhenEmpty);

        var serverConfig = new ServerConfig
        {
            ProtocolId = TestConstants.TestProtocolId,
            OverrideSendAndReceive = true,
            SendPacketOverride = (in Address to, ReadOnlySpan<byte> payload) => { },
            ReceivePacketOverride = (ref Address from, Span<byte> payload) => 0,
            SendLoopbackPacket = (int clientIndex, ReadOnlySpan<byte> payload, ulong sequence) => { },
        };
        TestConstants.PrivateKey.CopyTo(serverConfig.PrivateKey, 0);
        using var server = new Server("127.0.0.1:40001", serverConfig, 1000.0);
        server.Start(1);
        server.ConnectLoopbackClient(0, 0x11111111, ReadOnlySpan<byte>.Empty);
        Check.That(server.ClientConnected(0));
        server.ProcessLoopbackPacket(0, queued, 43);

        ArgumentException? serverError = null;
        try
        {
            server.ReceivePacket(0, shortBuffer, out _);
        }
        catch (ArgumentException e)
        {
            serverError = e;
        }
        Check.That(serverError != null);
        Check.That(serverError!.ParamName == "payload");

        int serverLength = server.ReceivePacket(0, fullBuffer, out ulong serverSequence);
        Check.That(serverLength == queued.Length);
        Check.That(serverSequence == 43UL);
        Check.That(fullBuffer.AsSpan(0, serverLength).SequenceEqual(queued));

        bool serverThrewWhenEmpty = false;
        try
        {
            server.ReceivePacket(0, shortBuffer, out _);
        }
        catch (ArgumentException)
        {
            serverThrewWhenEmpty = true;
        }
        Check.That(serverThrewWhenEmpty);
    }
}

// replay protection through PacketIO.ReadPacket within one session: the same
// encrypted datagram read twice, and a datagram that fails authentication.
// unit tests: no sockets, no real time (timestamps are fixed, starting at 1000).
internal static class SessionReplayTests
{
    private const ulong TestTimestamp = 1000;

    private static readonly bool[] Allowed = CreateAllowed();

    private static bool[] CreateAllowed()
    {
        var allowed = new bool[PacketType.NumPackets];
        allowed[PacketType.ConnectionKeepAlive] = true;
        allowed[PacketType.ConnectionPayload] = true;
        allowed[PacketType.ConnectionDisconnect] = true;
        return allowed;
    }

    private static byte[] WritePacket(int packetType, byte[] packetData, ulong sequence, byte[] key)
    {
        byte[] buffer = new byte[Defines.MaxPacketBytes];
        int bytes = PacketIO.WriteEncryptedPacket(buffer, packetType, packetData, sequence, key, TestConstants.TestProtocolId);
        Check.That(bytes > 0);
        return buffer.AsSpan(0, bytes).ToArray();
    }

    // ReadPacket decrypts in place, so every read gets its own copy of the datagram
    private static ReadPacketResult Read(byte[] datagram, byte[] receiveBuffer, byte[] key, ReplayProtection replayProtection)
    {
        datagram.CopyTo(receiveBuffer, 0);
        return PacketIO.ReadPacket(
            receiveBuffer.AsSpan(0, datagram.Length),
            hasReadPacketKey: true, key,
            TestConstants.TestProtocolId,
            TestTimestamp,
            hasPrivateKey: false, ReadOnlySpan<byte>.Empty,
            Allowed, replayProtection);
    }

    public static void TestReplayProtectionDuplicatePacket()
    {
        var rng = new TestRng(0x5EED1000);

        byte[] key = new byte[Protocol.KeyBytes];
        rng.Fill(key);

        byte[] payload = new byte[64];
        rng.Fill(payload);

        byte[] keepAliveData = new byte[8];

        byte[] receiveBuffer = new byte[Defines.MaxPacketBytes];

        var replayProtection = new ReplayProtection();

        byte[] payloadPacket = WritePacket(PacketType.ConnectionPayload, payload, 1000, key);

        // the first read of the datagram is accepted

        ReadPacketResult first = Read(payloadPacket, receiveBuffer, key, replayProtection);
        Check.That(first.Type == PacketType.ConnectionPayload);
        Check.That(first.Sequence == 1000);
        Check.That(first.DataLength == payload.Length);
        Check.That(receiveBuffer.AsSpan(first.DataOffset, first.DataLength).SequenceEqual(payload));
        Check.That(replayProtection.MostRecentSequence == 1000);

        // the identical datagram read again in the same session is ignored

        ReadPacketResult second = Read(payloadPacket, receiveBuffer, key, replayProtection);
        Check.That(second.Type == -1);

        // the next sequence is still accepted, and its duplicate ignored too

        byte[] keepAlivePacket = WritePacket(PacketType.ConnectionKeepAlive, keepAliveData, 1001, key);

        ReadPacketResult third = Read(keepAlivePacket, receiveBuffer, key, replayProtection);
        Check.That(third.Type == PacketType.ConnectionKeepAlive);
        Check.That(third.Sequence == 1001);

        Check.That(Read(keepAlivePacket, receiveBuffer, key, replayProtection).Type == -1);

        // an older sequence inside the window that was never received is still accepted once

        byte[] olderPacket = WritePacket(PacketType.ConnectionPayload, payload, 999, key);

        Check.That(Read(olderPacket, receiveBuffer, key, replayProtection).Type == PacketType.ConnectionPayload);
        Check.That(Read(olderPacket, receiveBuffer, key, replayProtection).Type == -1);
        Check.That(Read(payloadPacket, receiveBuffer, key, replayProtection).Type == -1);
    }

    public static void TestReplayProtectionFailedDecrypt()
    {
        var rng = new TestRng(0x5EED2000);

        byte[] key = new byte[Protocol.KeyBytes];
        rng.Fill(key);

        byte[] wrongKey = new byte[Protocol.KeyBytes];
        rng.Fill(wrongKey);

        byte[] payload = new byte[64];
        rng.Fill(payload);

        byte[] receiveBuffer = new byte[Defines.MaxPacketBytes];

        var replayProtection = new ReplayProtection();

        byte[] authentic = WritePacket(PacketType.ConnectionPayload, payload, 1000, key);

        // the same datagram with one byte of its tag changed fails authentication

        byte[] tampered = (byte[])authentic.Clone();
        tampered[tampered.Length - 1] ^= 0x01;

        Check.That(Read(tampered, receiveBuffer, key, replayProtection).Type == -1);
        Check.That(replayProtection.MostRecentSequence == 0);
        Check.That(!replayProtection.AlreadyReceived(1000));

        // so does a datagram at a much higher sequence under the wrong key

        byte[] forgedAhead = WritePacket(PacketType.ConnectionPayload, payload, 1000 + Defines.ReplayProtectionBufferSize * 4, wrongKey);

        Check.That(Read(forgedAhead, receiveBuffer, key, replayProtection).Type == -1);
        Check.That(replayProtection.MostRecentSequence == 0);
        Check.That(!replayProtection.AlreadyReceived(1000));

        // neither moved the window: the authentic datagram at that sequence is accepted

        ReadPacketResult result = Read(authentic, receiveBuffer, key, replayProtection);
        Check.That(result.Type == PacketType.ConnectionPayload);
        Check.That(result.Sequence == 1000);
        Check.That(receiveBuffer.AsSpan(result.DataOffset, result.DataLength).SequenceEqual(payload));
        Check.That(replayProtection.MostRecentSequence == 1000);

        // and once accepted, the tampered copy and the authentic copy are both ignored

        Check.That(Read(tampered, receiveBuffer, key, replayProtection).Type == -1);
        Check.That(Read(authentic, receiveBuffer, key, replayProtection).Type == -1);
        Check.That(replayProtection.MostRecentSequence == 1000);
    }
}
