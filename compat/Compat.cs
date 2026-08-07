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
        if (!ConnectTokenGenerator.Generate(addresses, addresses, 60, 15, clientId, SessionProtocolId, SessionPrivateKey, userData, connectToken))
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
            _ => Usage(),
        };
    }

    private static int Usage()
    {
        Console.WriteLine("usage: compat goldens <dir> | verify <dir> | mint <file> <address> | server <port> | client <port> <token>");
        return 1;
    }
}
