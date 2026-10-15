/*
    Compat.cs — the C# half of the netcode.cs interop gate.

    Mirrors compat/c/compat.c exactly: writes the same goldens from the same
    fixed keys/nonces/timestamps (byte identity is checked by interop.sh),
    verifies the other side's goldens through the real decrypt/read paths, and
    runs live client/server session legs over localhost UDP.

    Subcommands: goldens <dir> | verify <dir> | mint <file> <address> |
                 server <port> | client <port> <token-file>
    Exit code is the verdict.
*/

using System;
using System.Buffers.Binary;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using Netcode;

namespace Netcode.Compat;

internal static class Program
{
    private const ulong GoldenProtocolId = 0x1122334455667788UL;
    private const ulong GoldenClientId = 0x1122AABBCCDD3344UL;
    private const int GoldenTimeoutSeconds = 15;
    private const ulong GoldenExpireTimestamp = 0x1234567890ABCDEFUL;
    private const ulong GoldenCreateTimestamp = GoldenExpireTimestamp - 30;
    private const ulong GoldenChallengeSequence = 0xBADDUL;

    private const ulong SessionProtocolId = 0x1122334455667788UL;
    private const int SessionNumPayloads = 10;

    // TEST KEY ONLY — the fixed key from the C reference test suite. published in
    // two public repositories; obviously non-production.
    private static readonly byte[] SessionPrivateKey =
    {
        0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea,
        0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
        0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
        0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1,
    };

    private static void FillPattern(Span<byte> data, int offset)
    {
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(i + offset);
    }

    private static bool Verify(bool condition, string what)
    {
        if (!condition)
            Console.WriteLine($"verify failed: {what}");
        return condition;
    }

    private static (byte[] tokenKey, byte[] challengeKey, byte[] packetKey, byte[] nonce) GoldenKeys()
    {
        byte[] tokenKey = new byte[Protocol.KeyBytes];
        byte[] challengeKey = new byte[Protocol.KeyBytes];
        byte[] packetKey = new byte[Protocol.KeyBytes];
        byte[] nonce = new byte[Defines.ConnectTokenNonceBytes];
        FillPattern(tokenKey, 1);
        FillPattern(challengeKey, 4);
        FillPattern(packetKey, 5);
        FillPattern(nonce, 6);
        return (tokenKey, challengeKey, packetKey, nonce);
    }

    private static Address[] GoldenAddresses()
    {
        return new[]
        {
            Address.Parse("127.0.0.1:40000"),
            Address.Parse("[fe80::202:b3ff:fe1e:8329]:50000"),
        };
    }

    private static ConnectTokenPrivate GoldenPrivateTokenStruct()
    {
        var token = new ConnectTokenPrivate
        {
            ClientId = GoldenClientId,
            TimeoutSeconds = GoldenTimeoutSeconds,
            NumServerAddresses = 2,
        };
        Address[] addresses = GoldenAddresses();
        token.ServerAddresses[0] = addresses[0];
        token.ServerAddresses[1] = addresses[1];
        FillPattern(token.ClientToServerKey, 2);
        FillPattern(token.ServerToClientKey, 3);
        FillPattern(token.UserData, 0);
        return token;
    }

    private static byte[] BuildGoldenPrivateToken()
    {
        (byte[] tokenKey, _, _, byte[] nonce) = GoldenKeys();

        byte[] buffer = new byte[Defines.ConnectTokenPrivateBytes];
        GoldenPrivateTokenStruct().Write(buffer);

        if (!ConnectTokenPrivate.Encrypt(buffer, Defines.VersionInfo, GoldenProtocolId, GoldenExpireTimestamp, nonce, tokenKey))
            throw new InvalidOperationException("golden private token encryption failed");

        return buffer;
    }

    private static byte[] BuildGoldenChallengeToken()
    {
        (_, byte[] challengeKey, _, _) = GoldenKeys();

        var token = new ChallengeToken { ClientId = GoldenClientId };
        FillPattern(token.UserData, 0);

        byte[] buffer = new byte[Defines.ChallengeTokenBytes];
        token.Write(buffer);
        ChallengeToken.Encrypt(buffer, GoldenChallengeSequence, challengeKey);
        return buffer;
    }

    private static int DoGoldens(string dir)
    {
        (byte[] tokenKey, _, byte[] packetKey, byte[] nonce) = GoldenKeys();
        _ = tokenKey;

        // 1. encrypted private connect token

        byte[] privateToken = BuildGoldenPrivateToken();
        File.WriteAllBytes(Path.Combine(dir, "private_token.bin"), privateToken);

        // 2. public connect token wrapping it

        var connectToken = new ConnectTokenData();
        Defines.VersionInfo.CopyTo(connectToken.VersionInfo);
        connectToken.ProtocolId = GoldenProtocolId;
        connectToken.CreateTimestamp = GoldenCreateTimestamp;
        connectToken.ExpireTimestamp = GoldenExpireTimestamp;
        nonce.CopyTo(connectToken.Nonce, 0);
        privateToken.CopyTo(connectToken.PrivateData, 0);
        connectToken.NumServerAddresses = 2;
        Address[] addresses = GoldenAddresses();
        connectToken.ServerAddresses[0] = addresses[0];
        connectToken.ServerAddresses[1] = addresses[1];
        FillPattern(connectToken.ClientToServerKey, 2);
        FillPattern(connectToken.ServerToClientKey, 3);
        connectToken.TimeoutSeconds = GoldenTimeoutSeconds;

        byte[] publicToken = new byte[Protocol.ConnectTokenBytes];
        connectToken.Write(publicToken);
        File.WriteAllBytes(Path.Combine(dir, "public_token.bin"), publicToken);

        // 3. encrypted challenge token

        byte[] challengeToken = BuildGoldenChallengeToken();
        File.WriteAllBytes(Path.Combine(dir, "challenge_token.bin"), challengeToken);

        // 4. every packet type, fixed keys and sequences

        byte[] buffer = new byte[Defines.MaxPacketBytes * 2];
        int bytes;

        bytes = PacketIO.WriteConnectionRequestPacket(buffer, Defines.VersionInfo, GoldenProtocolId, GoldenExpireTimestamp, nonce, privateToken);
        File.WriteAllBytes(Path.Combine(dir, "packet_request.bin"), buffer.AsSpan(0, bytes).ToArray());

        bytes = PacketIO.WriteEncryptedPacket(buffer, PacketType.ConnectionDenied, ReadOnlySpan<byte>.Empty, 1UL << 63, packetKey, GoldenProtocolId);
        File.WriteAllBytes(Path.Combine(dir, "packet_denied.bin"), buffer.AsSpan(0, bytes).ToArray());

        byte[] challengeData = new byte[8 + Defines.ChallengeTokenBytes];
        BinaryPrimitives.WriteUInt64LittleEndian(challengeData.AsSpan(0, 8), GoldenChallengeSequence);
        challengeToken.CopyTo(challengeData.AsSpan(8));

        bytes = PacketIO.WriteEncryptedPacket(buffer, PacketType.ConnectionChallenge, challengeData, (1UL << 63) + 5, packetKey, GoldenProtocolId);
        File.WriteAllBytes(Path.Combine(dir, "packet_challenge.bin"), buffer.AsSpan(0, bytes).ToArray());

        bytes = PacketIO.WriteEncryptedPacket(buffer, PacketType.ConnectionResponse, challengeData, 0x1F, packetKey, GoldenProtocolId);
        File.WriteAllBytes(Path.Combine(dir, "packet_response.bin"), buffer.AsSpan(0, bytes).ToArray());

        byte[] keepAliveData = new byte[8];
        BinaryPrimitives.WriteUInt32LittleEndian(keepAliveData.AsSpan(0, 4), 5);
        BinaryPrimitives.WriteUInt32LittleEndian(keepAliveData.AsSpan(4, 4), 32);

        bytes = PacketIO.WriteEncryptedPacket(buffer, PacketType.ConnectionKeepAlive, keepAliveData, 0x11223344, packetKey, GoldenProtocolId);
        File.WriteAllBytes(Path.Combine(dir, "packet_keepalive.bin"), buffer.AsSpan(0, bytes).ToArray());

        byte[] payload = new byte[Defines.MaxPayloadBytes];
        FillPattern(payload, 0);

        bytes = PacketIO.WriteEncryptedPacket(buffer, PacketType.ConnectionPayload, payload, 1000, packetKey, GoldenProtocolId);
        File.WriteAllBytes(Path.Combine(dir, "packet_payload.bin"), buffer.AsSpan(0, bytes).ToArray());

        bytes = PacketIO.WriteEncryptedPacket(buffer, PacketType.ConnectionDisconnect, ReadOnlySpan<byte>.Empty, 7, packetKey, GoldenProtocolId);
        File.WriteAllBytes(Path.Combine(dir, "packet_disconnect.bin"), buffer.AsSpan(0, bytes).ToArray());

        Console.WriteLine($"goldens written to {dir}");
        return 0;
    }

    private static int DoVerify(string dir)
    {
        (byte[] tokenKey, byte[] challengeKey, byte[] packetKey, byte[] nonce) = GoldenKeys();

        Address[] expectedAddresses = GoldenAddresses();

        byte[] expectedUserData = new byte[Protocol.UserDataBytes];
        FillPattern(expectedUserData, 0);
        byte[] expectedC2S = new byte[Protocol.KeyBytes];
        byte[] expectedS2C = new byte[Protocol.KeyBytes];
        FillPattern(expectedC2S, 2);
        FillPattern(expectedS2C, 3);

        // 1. private connect token decrypts and reads back the golden fields

        byte[] privateToken = File.ReadAllBytes(Path.Combine(dir, "private_token.bin"));
        if (!Verify(privateToken.Length == Defines.ConnectTokenPrivateBytes, "private token size")) return 1;
        if (!Verify(ConnectTokenPrivate.Decrypt(privateToken, Defines.VersionInfo, GoldenProtocolId, GoldenExpireTimestamp, nonce, tokenKey), "private token decrypt")) return 1;

        var privateStruct = new ConnectTokenPrivate();
        if (!Verify(privateStruct.Read(privateToken), "private token read")) return 1;
        if (!Verify(privateStruct.ClientId == GoldenClientId, "private token client id")) return 1;
        if (!Verify(privateStruct.TimeoutSeconds == GoldenTimeoutSeconds, "private token timeout")) return 1;
        if (!Verify(privateStruct.NumServerAddresses == 2, "private token address count")) return 1;
        if (!Verify(privateStruct.ServerAddresses[0].Equals(expectedAddresses[0]), "private token address 0")) return 1;
        if (!Verify(privateStruct.ServerAddresses[1].Equals(expectedAddresses[1]), "private token address 1")) return 1;
        if (!Verify(privateStruct.ClientToServerKey.AsSpan().SequenceEqual(expectedC2S), "private token c2s key")) return 1;
        if (!Verify(privateStruct.ServerToClientKey.AsSpan().SequenceEqual(expectedS2C), "private token s2c key")) return 1;
        if (!Verify(privateStruct.UserData.AsSpan().SequenceEqual(expectedUserData), "private token user data")) return 1;

        // 2. public connect token reads back

        byte[] publicToken = File.ReadAllBytes(Path.Combine(dir, "public_token.bin"));
        var connectToken = new ConnectTokenData();
        if (!Verify(connectToken.Read(publicToken), "public token read")) return 1;
        if (!Verify(connectToken.ProtocolId == GoldenProtocolId, "public token protocol id")) return 1;
        if (!Verify(connectToken.CreateTimestamp == GoldenCreateTimestamp, "public token create timestamp")) return 1;
        if (!Verify(connectToken.ExpireTimestamp == GoldenExpireTimestamp, "public token expire timestamp")) return 1;
        if (!Verify(connectToken.TimeoutSeconds == GoldenTimeoutSeconds, "public token timeout")) return 1;
        if (!Verify(connectToken.NumServerAddresses == 2, "public token address count")) return 1;
        if (!Verify(connectToken.ServerAddresses[0].Equals(expectedAddresses[0]), "public token address 0")) return 1;
        if (!Verify(connectToken.ServerAddresses[1].Equals(expectedAddresses[1]), "public token address 1")) return 1;

        // 3. challenge token decrypts and reads back

        byte[] challengeToken = File.ReadAllBytes(Path.Combine(dir, "challenge_token.bin"));
        if (!Verify(challengeToken.Length == Defines.ChallengeTokenBytes, "challenge token size")) return 1;
        if (!Verify(ChallengeToken.Decrypt(challengeToken, GoldenChallengeSequence, challengeKey), "challenge token decrypt")) return 1;

        var challengeStruct = new ChallengeToken();
        if (!Verify(challengeStruct.Read(challengeToken), "challenge token read")) return 1;
        if (!Verify(challengeStruct.ClientId == GoldenClientId, "challenge token client id")) return 1;
        if (!Verify(challengeStruct.UserData.AsSpan().SequenceEqual(expectedUserData), "challenge token user data")) return 1;

        // 4. every packet type reads (and decrypts) back

        var allAllowed = new bool[PacketType.NumPackets];
        Array.Fill(allAllowed, true);

        ReadPacketResult ReadFile(string name, bool hasPrivateKey)
        {
            byte[] data = File.ReadAllBytes(Path.Combine(dir, name));
            return PacketIO.ReadPacket(data, hasReadPacketKey: true, packetKey, GoldenProtocolId, 0,
                hasPrivateKey, tokenKey, allAllowed, null);
        }

        {
            byte[] data = File.ReadAllBytes(Path.Combine(dir, "packet_request.bin"));
            ReadPacketResult result = PacketIO.ReadPacket(data, hasReadPacketKey: true, packetKey, GoldenProtocolId, 0,
                hasPrivateKey: true, tokenKey, allAllowed, null);
            if (!Verify(result.Type == PacketType.ConnectionRequest, "request packet type")) return 1;
            var token = new ConnectTokenPrivate();
            if (!Verify(token.Read(data.AsSpan(result.DataOffset, result.DataLength)), "request packet token read")) return 1;
            if (!Verify(token.ClientId == GoldenClientId, "request packet client id")) return 1;
        }

        {
            ReadPacketResult result = ReadFile("packet_denied.bin", false);
            if (!Verify(result.Type == PacketType.ConnectionDenied, "denied packet type")) return 1;
            if (!Verify(result.Sequence == 1UL << 63, "denied packet sequence")) return 1;
        }

        {
            byte[] data = File.ReadAllBytes(Path.Combine(dir, "packet_challenge.bin"));
            ReadPacketResult result = PacketIO.ReadPacket(data, true, packetKey, GoldenProtocolId, 0, false, ReadOnlySpan<byte>.Empty, allAllowed, null);
            if (!Verify(result.Type == PacketType.ConnectionChallenge, "challenge packet type")) return 1;
            if (!Verify(result.Sequence == (1UL << 63) + 5, "challenge packet sequence")) return 1;
            if (!Verify(BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(result.DataOffset, 8)) == GoldenChallengeSequence, "challenge token sequence")) return 1;
        }

        {
            ReadPacketResult result = ReadFile("packet_response.bin", false);
            if (!Verify(result.Type == PacketType.ConnectionResponse, "response packet type")) return 1;
            if (!Verify(result.Sequence == 0x1F, "response packet sequence")) return 1;
        }

        {
            byte[] data = File.ReadAllBytes(Path.Combine(dir, "packet_keepalive.bin"));
            ReadPacketResult result = PacketIO.ReadPacket(data, true, packetKey, GoldenProtocolId, 0, false, ReadOnlySpan<byte>.Empty, allAllowed, null);
            if (!Verify(result.Type == PacketType.ConnectionKeepAlive, "keepalive packet type")) return 1;
            if (!Verify(result.Sequence == 0x11223344, "keepalive packet sequence")) return 1;
            if (!Verify(BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(result.DataOffset, 4)) == 5, "keepalive client index")) return 1;
            if (!Verify(BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(result.DataOffset + 4, 4)) == 32, "keepalive max clients")) return 1;
        }

        {
            byte[] data = File.ReadAllBytes(Path.Combine(dir, "packet_payload.bin"));
            ReadPacketResult result = PacketIO.ReadPacket(data, true, packetKey, GoldenProtocolId, 0, false, ReadOnlySpan<byte>.Empty, allAllowed, null);
            if (!Verify(result.Type == PacketType.ConnectionPayload, "payload packet type")) return 1;
            if (!Verify(result.Sequence == 1000, "payload packet sequence")) return 1;
            if (!Verify(result.DataLength == Defines.MaxPayloadBytes, "payload packet size")) return 1;
            byte[] expectedPayload = new byte[Defines.MaxPayloadBytes];
            FillPattern(expectedPayload, 0);
            if (!Verify(data.AsSpan(result.DataOffset, result.DataLength).SequenceEqual(expectedPayload), "payload packet data")) return 1;
        }

        {
            ReadPacketResult result = ReadFile("packet_disconnect.bin", false);
            if (!Verify(result.Type == PacketType.ConnectionDisconnect, "disconnect packet type")) return 1;
            if (!Verify(result.Sequence == 7, "disconnect packet sequence")) return 1;
        }

        Console.WriteLine($"verify passed: {dir}");
        return 0;
    }

    private static int DoMint(string filename, string serverAddress)
    {
        byte[] connectToken = new byte[Protocol.ConnectTokenBytes];
        byte[] userData = new byte[Protocol.UserDataBytes];
        FillPattern(userData, 0);

        byte[] clientIdBytes = new byte[8];
        System.Security.Cryptography.RandomNumberGenerator.Fill(clientIdBytes);
        ulong clientId = BinaryPrimitives.ReadUInt64LittleEndian(clientIdBytes);

        string[] addresses = { serverAddress };
        if (!ConnectTokenGenerator.Generate(addresses, addresses, 30, 15, clientId, SessionProtocolId, SessionPrivateKey, userData, connectToken))
        {
            Console.WriteLine("error: failed to mint connect token");
            return 1;
        }

        File.WriteAllBytes(filename, connectToken);
        Console.WriteLine($"minted connect token (C#) -> {filename}");
        return 0;
    }

    private static int DoServer(int port)
    {
        var config = new ServerConfig { ProtocolId = SessionProtocolId };
        SessionPrivateKey.CopyTo(config.PrivateKey, 0);

        using var server = new Server($"127.0.0.1:{port}", config, 0.0);

        server.Start(1);

        byte[] payload = new byte[Protocol.MaxPacketSize];
        FillPattern(payload, 0);
        byte[] received = new byte[Protocol.MaxPacketSize];

        int payloadsReceived = 0;
        bool clientWasConnected = false;
        double time = 0.0;
        const double deltaTime = 0.01;
        const int iterations = 6000; // 60 seconds of real time

        Console.WriteLine($"C# server listening on 127.0.0.1:{port}");

        for (int i = 0; i < iterations; i++)
        {
            server.Update(time);

            if (server.ClientConnected(0))
            {
                clientWasConnected = true;

                server.SendPacket(0, payload);

                while (true)
                {
                    int bytes = server.ReceivePacket(0, received, out _);
                    if (bytes < 0)
                        break;
                    if (bytes != Protocol.MaxPacketSize || !received.AsSpan(0, bytes).SequenceEqual(payload))
                    {
                        Console.WriteLine("error: C# server received bad payload");
                        return 1;
                    }
                    payloadsReceived++;
                }
            }
            else if (clientWasConnected)
            {
                // the client disconnected. success requires that we saw its payloads and
                // that the disconnect was client initiated, not a timeout.
                DisconnectReason reason = server.ClientDisconnectReason(0);
                if (payloadsReceived >= SessionNumPayloads && reason == DisconnectReason.ClientDisconnect)
                {
                    Console.WriteLine($"C# server: client connected, {payloadsReceived} payloads received, clean client disconnect");
                    return 0;
                }
                Console.WriteLine($"error: C# server: payloadsReceived={payloadsReceived} disconnectReason={reason}");
                return 1;
            }

            Thread.Sleep(10);
            time += deltaTime;
        }

        Console.WriteLine("error: C# server: no client connected within the time limit");
        return 1;
    }

    private static int DoClient(int port, string tokenFile)
    {
        _ = port;

        byte[] connectToken = File.ReadAllBytes(tokenFile);
        if (connectToken.Length != Protocol.ConnectTokenBytes)
        {
            Console.WriteLine($"error: token file is {connectToken.Length} bytes");
            return 1;
        }

        using var client = new Client("0.0.0.0:0");

        client.Connect(connectToken);

        byte[] payload = new byte[Protocol.MaxPacketSize];
        FillPattern(payload, 0);
        byte[] received = new byte[Protocol.MaxPacketSize];

        int payloadsReceived = 0;
        int payloadsSent = 0;
        double time = 0.0;
        const double deltaTime = 0.01;
        const int iterations = 6000;

        for (int i = 0; i < iterations; i++)
        {
            client.Update(time);

            if (client.State == ClientState.Connected)
            {
                client.SendPacket(payload);
                payloadsSent++;

                while (true)
                {
                    int bytes = client.ReceivePacket(received, out _);
                    if (bytes < 0)
                        break;
                    if (bytes != Protocol.MaxPacketSize || !received.AsSpan(0, bytes).SequenceEqual(payload))
                    {
                        Console.WriteLine("error: C# client received bad payload");
                        return 1;
                    }
                    payloadsReceived++;
                }

                // keep sending past the receive threshold so the other side reliably
                // sees its quota before the disconnect lands
                if (payloadsReceived >= SessionNumPayloads && payloadsSent >= SessionNumPayloads * 2)
                {
                    Console.WriteLine($"C# client: connected as client {client.ClientIndex}, {payloadsReceived} payloads received, disconnecting");
                    client.Disconnect();
                    return 0;
                }
            }
            else if (client.State < ClientState.Disconnected)
            {
                Console.WriteLine($"error: C# client entered error state {Client.StateName(client.State)}");
                return 1;
            }

            Thread.Sleep(10);
            time += deltaTime;
        }

        Console.WriteLine($"error: C# client: only {payloadsReceived} payloads received");
        return 1;
    }

    private static int DoDiffPackets()
    {
        (byte[] tokenKey, _, byte[] packetKey, byte[] nonce) = GoldenKeys();

        byte[] privateToken = BuildGoldenPrivateToken();

        // A current timestamp that is well before the golden expire timestamp so no
        // token expires during the test.
        ulong currentTimestamp = GoldenExpireTimestamp - 1;

        var allAllowed = new bool[PacketType.NumPackets];
        Array.Fill(allAllowed, true);

        var replay = new ReplayProtection();

        string TypeName(int type) => type switch
        {
            PacketType.ConnectionRequest => "request",
            PacketType.ConnectionDenied => "denied",
            PacketType.ConnectionChallenge => "challenge",
            PacketType.ConnectionResponse => "response",
            PacketType.ConnectionKeepAlive => "keepalive",
            PacketType.ConnectionPayload => "payload",
            PacketType.ConnectionDisconnect => "disconnect",
            _ => "refused",
        };

        void PrintResult(int index, ReadPacketResult result)
        {
            string name = result.Type < 0 ? "refused" : TypeName(result.Type);
            Console.WriteLine($"{index} {name} {result.Sequence} {result.DataLength}");
        }

        // 0: valid connection request packet
        {
            byte[] buffer = new byte[Defines.MaxPacketBytes * 2];
            int bytes = PacketIO.WriteConnectionRequestPacket(buffer, Defines.VersionInfo, GoldenProtocolId, GoldenExpireTimestamp, nonce, privateToken);
            ReadPacketResult result = PacketIO.ReadPacket(buffer.AsSpan(0, bytes), true, packetKey, GoldenProtocolId, currentTimestamp, true, tokenKey, allAllowed, null);
            PrintResult(0, result);
        }

        // 1: bad prefix byte (invalid packet type / sequence-byte count)
        {
            byte[] buffer = new byte[Defines.MaxPacketBytes * 2];
            int bytes = PacketIO.WriteEncryptedPacket(buffer, PacketType.ConnectionPayload, new byte[100], 1000, packetKey, GoldenProtocolId);
            buffer[0] = 0x70; // type 0, 7 sequence bytes (out of range)
            ReadPacketResult result = PacketIO.ReadPacket(buffer.AsSpan(0, bytes), true, packetKey, GoldenProtocolId, currentTimestamp, false, ReadOnlySpan<byte>.Empty, allAllowed, null);
            PrintResult(1, result);
        }

        // 2: truncated connection request packet
        {
            byte[] buffer = new byte[Defines.MaxPacketBytes * 2];
            int bytes = PacketIO.WriteConnectionRequestPacket(buffer, Defines.VersionInfo, GoldenProtocolId, GoldenExpireTimestamp, nonce, privateToken);
            ReadPacketResult result = PacketIO.ReadPacket(buffer.AsSpan(0, bytes - 1), true, packetKey, GoldenProtocolId, currentTimestamp, true, tokenKey, allAllowed, null);
            PrintResult(2, result);
        }

        // 3: wrong connection request packet size
        {
            byte[] buffer = new byte[Defines.MaxPacketBytes * 2];
            int bytes = PacketIO.WriteConnectionRequestPacket(buffer, Defines.VersionInfo, GoldenProtocolId, GoldenExpireTimestamp, nonce, privateToken);
            ReadPacketResult result = PacketIO.ReadPacket(buffer.AsSpan(0, bytes - 2), true, packetKey, GoldenProtocolId, currentTimestamp, true, tokenKey, allAllowed, null);
            PrintResult(3, result);
        }

        // 4: valid encrypted payload packet
        {
            byte[] payload = new byte[100];
            for (int i = 0; i < payload.Length; i++) payload[i] = (byte)i;
            byte[] buffer = new byte[Defines.MaxPacketBytes * 2];
            int bytes = PacketIO.WriteEncryptedPacket(buffer, PacketType.ConnectionPayload, payload, 1000, packetKey, GoldenProtocolId);
            ReadPacketResult result = PacketIO.ReadPacket(buffer.AsSpan(0, bytes), true, packetKey, GoldenProtocolId, currentTimestamp, false, ReadOnlySpan<byte>.Empty, allAllowed, replay);
            PrintResult(4, result);
        }

        // 5: replayed payload packet (same sequence, same replay state)
        {
            byte[] payload = new byte[100];
            for (int i = 0; i < payload.Length; i++) payload[i] = (byte)i;
            byte[] buffer = new byte[Defines.MaxPacketBytes * 2];
            int bytes = PacketIO.WriteEncryptedPacket(buffer, PacketType.ConnectionPayload, payload, 1000, packetKey, GoldenProtocolId);
            ReadPacketResult result = PacketIO.ReadPacket(buffer.AsSpan(0, bytes), true, packetKey, GoldenProtocolId, currentTimestamp, false, ReadOnlySpan<byte>.Empty, allAllowed, replay);
            PrintResult(5, result);
        }

        // 6: wrong version info in connection request
        {
            byte[] buffer = new byte[Defines.MaxPacketBytes * 2];
            int bytes = PacketIO.WriteConnectionRequestPacket(buffer, Defines.VersionInfo, GoldenProtocolId, GoldenExpireTimestamp, nonce, privateToken);
            buffer[1] = (byte)'X';
            ReadPacketResult result = PacketIO.ReadPacket(buffer.AsSpan(0, bytes), true, packetKey, GoldenProtocolId, currentTimestamp, true, tokenKey, allAllowed, null);
            PrintResult(6, result);
        }

        // 7: wrong protocol id in connection request
        {
            byte[] buffer = new byte[Defines.MaxPacketBytes * 2];
            int bytes = PacketIO.WriteConnectionRequestPacket(buffer, Defines.VersionInfo, GoldenProtocolId, GoldenExpireTimestamp, nonce, privateToken);
            BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(1 + Defines.VersionInfoBytes, 8), ~GoldenProtocolId);
            ReadPacketResult result = PacketIO.ReadPacket(buffer.AsSpan(0, bytes), true, packetKey, GoldenProtocolId, currentTimestamp, true, tokenKey, allAllowed, null);
            PrintResult(7, result);
        }

        return 0;
    }

    // The receive-drain differential. The same scripted receive queues run
    // through the C reference (compat/c/compat.c "drain") and through this port
    // ("drain" here); scripts/interop.sh diffs the two transcripts byte for
    // byte. Queue values: > 0 is a junk datagram of that byte length, -1 is
    // skip (an empty datagram or a receive error), 0 is would-block (nothing
    // more). Override transports only, time passed in, no sockets, no clock.

    private sealed class DrainScript
    {
        private readonly int[] _script;
        private int _index;

        public int Consumed;
        public int Processed;

        public DrainScript(params int[] script) => _script = script;

        public int Receive(ref Address from, Span<byte> packetData)
        {
            int result = _index < _script.Length ? _script[_index] : 0;
            _index++;
            Consumed++;

            if (result > 0)
            {
                Processed++;
                for (int i = 0; i < result; i++)
                    packetData[i] = 0xFF; // junk: an invalid prefix byte that every reader refuses
                from = Address.Parse("203.0.113.7:12345");
            }

            return result;
        }

        public void Send(in Address to, ReadOnlySpan<byte> packetData)
        {
        }
    }

    private static int[] JunkQueue(int count)
    {
        var queue = new int[count];
        Array.Fill(queue, 11);
        return queue;
    }

    private static void DrainServer(string queueName, params int[] queue)
    {
        var config = new ServerConfig { ProtocolId = SessionProtocolId, OverrideSendAndReceive = true };
        SessionPrivateKey.CopyTo(config.PrivateKey, 0);
        var script = new DrainScript(queue);
        config.SendPacketOverride = script.Send;
        config.ReceivePacketOverride = script.Receive;

        using var server = new Server("127.0.0.1:40000", config, 0.0);
        server.Start(1);

        server.Update(1.0);

        Console.WriteLine($"{queueName} server consumed {script.Consumed} processed {script.Processed}");
    }

    private static void DrainClient(string queueName, params int[] queue)
    {
        var config = new ClientConfig { OverrideSendAndReceive = true };
        var script = new DrainScript(queue);
        config.SendPacketOverride = script.Send;
        config.ReceivePacketOverride = script.Receive;

        using var client = new Client("0.0.0.0:0", config, 0.0);

        client.Update(1.0);

        Console.WriteLine($"{queueName} client consumed {script.Consumed} processed {script.Processed}");
    }

    private static int DoDrain()
    {
        // [junk, EMPTY, junk, junk]
        DrainServer("q1", 11, -1, 11, 11);
        DrainClient("q1", 11, -1, 11, 11);

        // [EMPTY, EMPTY, EMPTY, junk]
        DrainServer("q2", -1, -1, -1, 11);
        DrainClient("q2", -1, -1, -1, 11);

        // MAX_RECEIVE_PACKETS + 10 junk datagrams
        DrainServer("q3", JunkQueue(Defines.ServerMaxReceivePackets + 10));
        DrainClient("q3", JunkQueue(Defines.ClientMaxReceivePackets + 10));

        // a queue that ends with a would-block
        DrainServer("q4", 11, 11, 0);
        DrainClient("q4", 11, 11, 0);

        // classifier rows (C: netcode_classify_receive_result; port: ClassifyReceiveResult)
        Console.WriteLine($"classify (0,0) -> {NetcodeSocket.ClassifyReceiveResult(0, SocketError.Success)}");
        Console.WriteLine($"classify (-1,wouldblock) -> {NetcodeSocket.ClassifyReceiveResult(-1, SocketError.WouldBlock)}");
        Console.WriteLine($"classify (-1,other) -> {NetcodeSocket.ClassifyReceiveResult(-1, SocketError.ConnectionRefused)}");
        Console.WriteLine($"classify (5,0) -> {NetcodeSocket.ClassifyReceiveResult(5, SocketError.Success)}");

        return 0;
    }

    private static ConnectTokenData ScenarioToken(ulong id, byte user, int seed)
    {
        Address serverAddress = Address.Parse("127.0.0.1:40000");
        var privateToken = new ConnectTokenPrivate
        {
            ClientId = id,
            TimeoutSeconds = 15,
            NumServerAddresses = 1,
        };
        privateToken.ServerAddresses[0] = serverAddress;
        FillPattern(privateToken.ClientToServerKey, 10 * seed);
        FillPattern(privateToken.ServerToClientKey, 10 * seed + 1);
        Array.Fill(privateToken.UserData, user);

        var token = new ConnectTokenData
        {
            ProtocolId = SessionProtocolId,
            CreateTimestamp = 1000,
            ExpireTimestamp = 1030,
            TimeoutSeconds = 15,
            NumServerAddresses = 1,
        };
        Defines.VersionInfo.CopyTo(token.VersionInfo);
        token.ServerAddresses[0] = serverAddress;
        FillPattern(token.Nonce, 10 * seed + 2);
        privateToken.ClientToServerKey.CopyTo(token.ClientToServerKey, 0);
        privateToken.ServerToClientKey.CopyTo(token.ServerToClientKey, 0);
        privateToken.Write(token.PrivateData);
        if (!ConnectTokenPrivate.Encrypt(token.PrivateData, token.VersionInfo, token.ProtocolId,
                token.ExpireTimestamp, token.Nonce, SessionPrivateKey))
            throw new InvalidOperationException("scenario token encryption failed");
        return token;
    }

    private static int DoChallengeMapping(string inputDir)
    {
        byte[] sent = Array.Empty<byte>();
        var config = new ServerConfig { ProtocolId = SessionProtocolId, OverrideSendAndReceive = true };
        SessionPrivateKey.CopyTo(config.PrivateKey, 0);
        config.SendPacketOverride = (in Address to, ReadOnlySpan<byte> data) => sent = data.ToArray();
        config.ReceivePacketOverride = (ref Address from, Span<byte> data) => 0;
        using var server = new Server("127.0.0.1:40000", config, 0.0);
        server.Start(4);
        byte[] fixedChallengeKey = new byte[Protocol.KeyBytes];
        FillPattern(fixedChallengeKey, 77);
        server.SetChallengeKeyForTest(fixedChallengeKey);
        server.SetConnectTokenExpiryFloorForTest(1000);
        Address x = Address.Parse("127.0.0.1:50000");
        Address y = Address.Parse("127.0.0.1:50001");
        ConnectTokenData a = ScenarioToken(0x1111, 0xA1, 1);
        ConnectTokenData b = ScenarioToken(0x2222, 0xB2, 2);
        ConnectTokenData c = ScenarioToken(0x3333, 0xC3, 3);
        foreach ((string name, ConnectTokenData token) in new[]
                 { ("token-a.bin", a), ("token-b.bin", b), ("token-c.bin", c) })
        {
            byte[] bytes = new byte[Protocol.ConnectTokenBytes];
            token.Write(bytes);
            File.WriteAllBytes(Path.Combine(inputDir, name), bytes);
        }

        void Request(in Address from, ConnectTokenData token, double logicalTime, string name)
        {
            byte[] wire = new byte[Defines.MaxPacketBytes];
            int bytes = PacketIO.WriteConnectionRequestPacket(wire, token.VersionInfo, token.ProtocolId,
                token.ExpireTimestamp, token.Nonce, token.PrivateData);
            File.WriteAllBytes(Path.Combine(inputDir, name), wire.AsSpan(0, bytes).ToArray());
            server.ProcessPacketAtTimestamp(in from, wire.AsSpan(0, bytes), 1001, logicalTime);
        }

        byte[] Challenge(ConnectTokenData token)
        {
            byte[] wire = (byte[])sent.Clone();
            bool[] allowed = new bool[PacketType.NumPackets];
            allowed[PacketType.ConnectionChallenge] = true;
            ReadPacketResult packet = PacketIO.ReadPacket(wire, true, token.ServerToClientKey,
                SessionProtocolId, 1001, false, ReadOnlySpan<byte>.Empty, allowed, null);
            if (packet.Type != PacketType.ConnectionChallenge)
                throw new InvalidOperationException("scenario challenge was not received");
            return wire.AsSpan(packet.DataOffset, packet.DataLength).ToArray();
        }

        void Response(in Address from, ConnectTokenData token, byte[] challenge, ulong sequence, double logicalTime, string name)
        {
            byte[] wire = new byte[Defines.MaxPacketBytes];
            int bytes = PacketIO.WriteEncryptedPacket(wire, PacketType.ConnectionResponse,
                challenge, sequence, token.ClientToServerKey, SessionProtocolId);
            File.WriteAllBytes(Path.Combine(inputDir, name), wire.AsSpan(0, bytes).ToArray());
            server.ProcessPacketAtTimestamp(in from, wire.AsSpan(0, bytes), 1001, logicalTime);
        }

        void Print(string step)
        {
            ulong[] ids = new ulong[server.NumConnectedClients];
            byte[] users = new byte[ids.Length];
            int count = 0;
            for (int slot = 0; slot < server.MaxClients; slot++)
                if (server.ClientConnected(slot))
                {
                    ids[count] = server.ClientId(slot);
                    users[count] = server.ClientUserData(slot)[0];
                    count++;
                }
            Array.Sort(ids, users);
            string idText = count == 0 ? "-" : string.Join(",", Array.ConvertAll(ids, id => id.ToString("x4")));
            string userText = count == 0 ? "-" : string.Join(",", Array.ConvertAll(users, value => value.ToString("x2")));
            Console.WriteLine($"{step} connected {idText} userdata {userText}");
        }

        Request(in x, a, 0.0, "01-request-A.bin");
        byte[] challengeA = Challenge(a);
        File.WriteAllBytes(Path.Combine(inputDir, "challenge-A.bin"), challengeA);
        Print("request-A");
        Request(in y, b, 0.1, "02-request-B.bin");
        byte[] challengeB = Challenge(b);
        File.WriteAllBytes(Path.Combine(inputDir, "challenge-B.bin"), challengeB);
        Print("request-B");
        Response(in y, b, challengeA, 1, 0.2, "03-response-Y-A.bin");
        Print("response-Y-A");
        Response(in y, b, challengeB, 2, 0.3, "04-response-Y-B.bin");
        Print("response-Y-B");
        Request(in x, c, 0.4, "05-request-C1.bin");
        byte[] challengeCFirst = Challenge(c);
        File.WriteAllBytes(Path.Combine(inputDir, "challenge-C1.bin"), challengeCFirst);
        Print("request-C1");
        Request(in x, c, 0.5, "06-request-C2.bin");
        byte[] challengeCSecond = Challenge(c);
        File.WriteAllBytes(Path.Combine(inputDir, "challenge-C2.bin"), challengeCSecond);
        if (BinaryPrimitives.ReadUInt64LittleEndian(challengeCFirst) == BinaryPrimitives.ReadUInt64LittleEndian(challengeCSecond))
            throw new InvalidOperationException("two challenges for C reused one sequence");
        Print("request-C2");
        Response(in x, c, challengeA, 1, 0.6, "07-response-X-A.bin");
        Print("response-X-A");
        Response(in x, c, challengeCFirst, 2, 0.7, "08-response-X-C1.bin");
        Print("response-X-C1");
        return 0;
    }

    private static int DoNonces()
    {
        NetcodeLog.Level = LogLevel.None;
        var serverConfig = new ServerConfig
        {
            ProtocolId = SessionProtocolId,
            OverrideSendAndReceive = true,
            SendPacketOverride = (in Address to, ReadOnlySpan<byte> data) => { },
            ReceivePacketOverride = (ref Address from, Span<byte> data) => 0,
        };
        SessionPrivateKey.CopyTo(serverConfig.PrivateKey, 0);

        using var serverA = new Server("127.0.0.1:40000", serverConfig, 0.0);
        using var serverB = new Server("127.0.0.1:40001", serverConfig, 0.0);
        serverA.Start(1);
        serverB.Start(1);
        ulong floor = 1UL << 63;
        ulong first = serverA.GlobalSequence;
        Console.WriteLine($"fresh a-ge {(serverA.GlobalSequence >= floor ? 1 : 0)}");
        Console.WriteLine($"fresh b-ge {(serverB.GlobalSequence >= floor ? 1 : 0)}");
        Console.WriteLine($"fresh differ {(serverA.GlobalSequence != serverB.GlobalSequence ? 1 : 0)}");
        serverA.Stop();
        serverA.Start(1);
        Console.WriteLine($"restart ge {(serverA.GlobalSequence >= floor ? 1 : 0)}");
        Console.WriteLine($"restart differ {(serverA.GlobalSequence != first ? 1 : 0)}");

        var clientConfig = new ClientConfig
        {
            OverrideSendAndReceive = true,
            SendPacketOverride = (in Address to, ReadOnlySpan<byte> data) => { },
            ReceivePacketOverride = (ref Address from, Span<byte> data) => 0,
        };
        using var client = new Client("127.0.0.1:50000", clientConfig, 0.0);
        byte[] userData = new byte[Protocol.UserDataBytes];
        Array.Fill(userData, (byte)1);
        byte[] connectToken = new byte[Protocol.ConnectTokenBytes];
        if (!ConnectTokenGenerator.Generate(new[] { "127.0.0.1:40000" }, new[] { "127.0.0.1:40000" }, 30, 15, 1, SessionProtocolId, SessionPrivateKey, userData, connectToken))
            return 1;
        client.Connect(connectToken);
        client.Disconnect();
        client.Connect(connectToken);
        Console.WriteLine($"client reuse {Client.StateName(client.State)}");
        return 0;
    }

    private static int DoTokenLifetimes()
    {
        NetcodeLog.Level = LogLevel.None;
        byte[] sent = Array.Empty<byte>();
        var config = new ServerConfig { ProtocolId = SessionProtocolId, OverrideSendAndReceive = true };
        SessionPrivateKey.CopyTo(config.PrivateKey, 0);
        config.SendPacketOverride = (in Address to, ReadOnlySpan<byte> data) => sent = data.ToArray();
        config.ReceivePacketOverride = (ref Address from, Span<byte> data) => 0;
        using var server = new Server("127.0.0.1:40000", config, 0.0);
        server.Start(4);
        server.SetConnectTokenExpiryFloorForTest(1000);
        Address x = Address.Parse("127.0.0.1:50000");

        ConnectTokenData Token(int timeout)
        {
            ConnectTokenData token = ScenarioToken(0x1111, 0xA1, 1);
            if (!ConnectTokenPrivate.Decrypt(token.PrivateData, token.VersionInfo, token.ProtocolId,
                    token.ExpireTimestamp, token.Nonce, SessionPrivateKey)) throw new InvalidOperationException();
            var privateToken = new ConnectTokenPrivate();
            if (!privateToken.Read(token.PrivateData)) throw new InvalidOperationException();
            privateToken.TimeoutSeconds = timeout;
            privateToken.Write(token.PrivateData);
            if (!ConnectTokenPrivate.Encrypt(token.PrivateData, token.VersionInfo, token.ProtocolId,
                    token.ExpireTimestamp, token.Nonce, SessionPrivateKey)) throw new InvalidOperationException();
            token.TimeoutSeconds = timeout;
            return token;
        }

        void Request(in Address from, ConnectTokenData token, double logicalTime)
        {
            byte[] wire = new byte[Defines.MaxPacketBytes];
            int bytes = PacketIO.WriteConnectionRequestPacket(wire, token.VersionInfo, token.ProtocolId,
                token.ExpireTimestamp, token.Nonce, token.PrivateData);
            server.ProcessPacketAtTimestamp(in from, wire.AsSpan(0, bytes), 1001, logicalTime);
        }

        foreach (int timeout in new[] { -1, 0, 1, 5, 30 })
        {
            ConnectTokenData token = Token(timeout);
            Request(in x, token, 0.0);
            int offset = -1;
            for (int t = 0; t <= 40; t++)
            {
                server.Update(t);
                if (server.NumEncryptionMappings == 0) { offset = t; break; }
            }
            Console.WriteLine($"timeout {timeout} -> {(offset < 0 ? "never" : offset.ToString())}");
            server.Stop();
            server.Start(4);
            server.SetConnectTokenExpiryFloorForTest(1000);

            Request(in x, token, 0.0);
            byte[] challenge = (byte[])sent.Clone();
            bool[] allowed = new bool[PacketType.NumPackets];
            allowed[PacketType.ConnectionChallenge] = true;
            ReadPacketResult packet = PacketIO.ReadPacket(challenge, true, token.ServerToClientKey,
                SessionProtocolId, 1001, false, ReadOnlySpan<byte>.Empty, allowed, null);
            if (packet.Type != PacketType.ConnectionChallenge) return 1;
            byte[] responseData = challenge.AsSpan(packet.DataOffset, packet.DataLength).ToArray();
            byte[] response = new byte[Defines.MaxPacketBytes];
            int responseBytes = PacketIO.WriteEncryptedPacket(response, PacketType.ConnectionResponse,
                responseData, 1, token.ClientToServerKey, SessionProtocolId);
            server.Update(0.1);
            server.ProcessPacketAtTimestamp(in x, response.AsSpan(0, responseBytes), 1001, 0.1);
            Console.WriteLine($"response {timeout} -> {(server.NumConnectedClients == 1 ? "connects" : "refused")}");
            server.Stop();
            server.Start(4);
            server.SetConnectTokenExpiryFloorForTest(1000);
        }

        ulong[] expiries = { ulong.MaxValue, 1060, 1031, 1030, 1001, 1000 };
        string[] expiryNames = { "max", "plus60", "plus31", "plus30", "plus1", "expired" };
        ConnectTokenData expiryToken = Token(15);
        for (int i = 0; i < expiries.Length; i++)
        {
            byte[] privateData = (byte[])expiryToken.PrivateData.Clone();
            if (!ConnectTokenPrivate.Decrypt(privateData, expiryToken.VersionInfo, expiryToken.ProtocolId,
                    expiryToken.ExpireTimestamp, expiryToken.Nonce, SessionPrivateKey)) return 1;
            if (!ConnectTokenPrivate.Encrypt(privateData, expiryToken.VersionInfo, expiryToken.ProtocolId,
                    expiries[i], expiryToken.Nonce, SessionPrivateKey)) return 1;
            byte[] wire = new byte[Defines.MaxPacketBytes];
            int bytes = PacketIO.WriteConnectionRequestPacket(wire, expiryToken.VersionInfo,
                expiryToken.ProtocolId, expiries[i], expiryToken.Nonce, privateData);
            bool[] allowed = new bool[PacketType.NumPackets];
            allowed[PacketType.ConnectionRequest] = true;
            ReadPacketResult packet = PacketIO.ReadPacket(wire.AsSpan(0, bytes), true,
                ReadOnlySpan<byte>.Empty, SessionProtocolId, 1000, true,
                SessionPrivateKey, allowed, null, 1000, 30);
            Console.WriteLine($"expiry {expiryNames[i]} -> {(packet.Type == PacketType.ConnectionRequest ? "accepted" : "refused")}");
        }

        return 0;
    }

    private static int DoClientAddress()
    {
        NetcodeLog.Level = LogLevel.None;
        var config = new ClientConfig
        {
            OverrideSendAndReceive = true,
            SendPacketOverride = (in Address to, ReadOnlySpan<byte> data) => { },
            ReceivePacketOverride = (ref Address from, Span<byte> data) => 0,
        };
        using var client = new Client("0.0.0.0:50000", config, 0.0);
        client.SocketAvailabilityOverride = type => Client.CanReach(type, true, false, false);

        (string name, string[] addresses)[] cases =
        {
            ("v6", new[] { "[::1]:40000" }),
            ("v6v4", new[] { "[::1]:40000", "127.0.0.1:40000" }),
            ("v4", new[] { "127.0.0.1:40000" }),
            ("v4v6", new[] { "127.0.0.1:40000", "[::1]:40000" }),
        };
        for (int i = 0; i < cases.Length; i++)
        {
            (string name, string[] addresses) = cases[i];
            ConnectTokenData connectToken = ScenarioToken(0x1111, 0xA1, i + 1);
            connectToken.NumServerAddresses = addresses.Length;
            for (int j = 0; j < addresses.Length; j++)
                connectToken.ServerAddresses[j] = Address.Parse(addresses[j]);
            byte[] token = new byte[Protocol.ConnectTokenBytes];
            connectToken.Write(token);
            client.Connect(token);
            if (name == "v4v6") client.Update(16.0);
            int index = client.State == ClientState.SendingConnectionRequest
                ? client.ServerAddressIndex
                : -1;
            Console.WriteLine($"{name} state {Client.StateName(client.State)} address {(index < 0 ? "none" : index.ToString())}");
        }

        return 0;
    }

    private static int Main(string[] args)
    {
        NetcodeLog.Level = LogLevel.Error;

        return args switch
        {
            ["goldens", var dir] => DoGoldens(dir),
            ["verify", var dir] => DoVerify(dir),
            ["mint", var file, var address] => DoMint(file, address),
            ["server", var port] => DoServer(int.Parse(port)),
            ["client", var port, var token] => DoClient(int.Parse(port), token),
            ["diffpackets"] => DoDiffPackets(),
            ["drain"] => DoDrain(),
            ["nonces"] => DoNonces(),
            ["challenge-mapping", var inputDir] => DoChallengeMapping(inputDir),
            ["token-lifetimes"] => DoTokenLifetimes(),
            ["client-address"] => DoClientAddress(),
            _ => Usage(),
        };
    }

    private static int Usage()
    {
        Console.WriteLine("usage: compat goldens <dir> | verify <dir> | mint <file> <address> | server <port> | client <port> <token> | diffpackets | drain | nonces");
        return 1;
    }
}
