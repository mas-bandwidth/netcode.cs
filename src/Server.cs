/*
    Server.cs — the netcode dedicated server (netcode_server_t).

    The server has no state machine of its own beyond stopped/started — all other
    state is per-client (deliberate, mirrors the C library). Flat arrays and
    linear scans for client lookup and the encryption mapping search are also
    deliberate: netcode targets ~100 players, and an attacker controls the keys
    (source addresses), so a hash table could be driven into its worst case;
    linear is the hardened choice.

    Copyright © 2026 Más Bandwidth LLC. Licensed under AGPL-3.0 (see LICENSE).
*/

using System;
using System.Buffers.Binary;

namespace Netcode
{
    /// <summary>Why server creation failed (carried by NetcodeException.ErrorCode). Bind failures
    /// are reported separately because a port already in use is the common operational failure.</summary>
    public enum ServerCreateError
    {
        /// <summary>No error.</summary>
        None = 0,
        /// <summary>The public address failed to parse.</summary>
        ParseAddressFailed = 1,
        /// <summary>The second public address failed to parse.</summary>
        ParseAddress2Failed = 2,
        /// <summary>The IPv4 socket could not be created.</summary>
        CreateSocketIpv4Failed = 3,
        /// <summary>The IPv6 socket could not be created.</summary>
        CreateSocketIpv6Failed = 4,
        /// <summary>The IPv4 socket could not be bound (port likely in use).</summary>
        BindSocketIpv4Failed = 5,
        /// <summary>The IPv6 socket could not be bound (port likely in use).</summary>
        BindSocketIpv6Failed = 6,
        /// <summary>OverrideSendAndReceive was set without both override callbacks.</summary>
        MissingOverrideCallback = 8,
    }

    /// <summary>Why the client in a server slot was last disconnected. Recorded before the
    /// connect/disconnect callback fires so it can be queried from inside the callback.</summary>
    public enum DisconnectReason
    {
        /// <summary>Never disconnected (or the slot was reset).</summary>
        None = 0,
        /// <summary>The client stopped sending packets and timed out.</summary>
        TimedOut = 1,
        /// <summary>The client sent a disconnect packet.</summary>
        ClientDisconnect = 2,
        /// <summary>The server disconnected the client.</summary>
        ServerDisconnect = 3,
    }

    /// <summary>Server configuration. Mirrors netcode_server_config_t.</summary>
    public sealed class ServerConfig
    {
        /// <summary>64-bit value unique to this game/application. Must match the connect tokens.</summary>
        public ulong ProtocolId;
        /// <summary>The 32-byte private key shared between the backend and dedicated servers.
        /// Never embed a production key in a client.</summary>
        public byte[] PrivateKey = new byte[Protocol.KeyBytes];
        /// <summary>Route packets through a deterministic network simulator instead of sockets.</summary>
        public NetworkSimulator? Simulator;
        /// <summary>(clientIndex, connected). connected=true on connect, false on disconnect.</summary>
        public Action<int, bool>? OnClientConnectDisconnect;
        /// <summary>Called to deliver payloads sent to a loopback client slot.</summary>
        public SendLoopbackPacketDelegate? SendLoopbackPacket;
        /// <summary>When true, no sockets are created and SendPacketOverride/ReceivePacketOverride carry the traffic.</summary>
        public bool OverrideSendAndReceive;
        /// <summary>Outgoing packet hook (used when OverrideSendAndReceive is true).</summary>
        public SendPacketOverrideDelegate? SendPacketOverride;
        /// <summary>Incoming packet hook (used when OverrideSendAndReceive is true).</summary>
        public ReceivePacketOverrideDelegate? ReceivePacketOverride;
        /// <summary>Tag outgoing packets DSCP EF (low latency). Off by default; no-op on Windows.</summary>
        public bool EnablePacketTagging;
    }

    /// <summary>
    /// The netcode dedicated server. Non-blocking, update-loop driven: create it,
    /// call Start(maxClients), then call Update(time) every frame and poll
    /// per-client state / ReceivePacket.
    /// </summary>
    public sealed class Server : IDisposable
    {
        internal const uint FlagIgnoreConnectionRequestPackets = 1;
        internal const uint FlagIgnoreConnectionResponsePackets = 1 << 1;

        private const int MaxConnectTokenEntries = Protocol.MaxClients * 8;

        private static readonly bool[] AllowedPackets = BuildAllowedPackets();

        private static bool[] BuildAllowedPackets()
        {
            var allowed = new bool[PacketType.NumPackets];
            allowed[PacketType.ConnectionRequest] = true;
            allowed[PacketType.ConnectionResponse] = true;
            allowed[PacketType.ConnectionKeepAlive] = true;
            allowed[PacketType.ConnectionPayload] = true;
            allowed[PacketType.ConnectionDisconnect] = true;
            return allowed;
        }

        private readonly ServerConfig _config;
        private readonly byte[] _privateKey = new byte[Protocol.KeyBytes];
        private NetcodeSocket? _socketIpv4;
        private NetcodeSocket? _socketIpv6;
        private Address _address;
        private Address _address2;
        internal uint Flags;
        private double _time;
        private bool _running;
        private int _maxClients;
        private int _numConnectedClients;
        private ulong _globalSequence;
        private ulong _challengeSequence;
        private readonly byte[] _challengeKey = new byte[Protocol.KeyBytes];
        private readonly bool[] _clientConnected = new bool[Protocol.MaxClients];
        private readonly int[] _clientTimeout = new int[Protocol.MaxClients];
        private readonly bool[] _clientLoopback = new bool[Protocol.MaxClients];
        private readonly bool[] _clientConfirmed = new bool[Protocol.MaxClients];
        private readonly DisconnectReason[] _clientDisconnectReason = new DisconnectReason[Protocol.MaxClients];
        private readonly int[] _clientEncryptionIndex = new int[Protocol.MaxClients];
        private readonly ulong[] _clientId = new ulong[Protocol.MaxClients];
        private readonly ulong[] _clientSequence = new ulong[Protocol.MaxClients];
        private readonly double[] _clientLastPacketSendTime = new double[Protocol.MaxClients];
        private readonly double[] _clientLastPacketReceiveTime = new double[Protocol.MaxClients];
        private readonly byte[] _clientUserData = new byte[Protocol.MaxClients * Protocol.UserDataBytes];
        private readonly ReplayProtection[] _clientReplayProtection = new ReplayProtection[Protocol.MaxClients];
        private readonly PacketQueue[] _clientPacketQueue = new PacketQueue[Protocol.MaxClients];
        private readonly Address[] _clientAddress = new Address[Protocol.MaxClients];

        // connect token single-use history. the find-or-add scan is constant time
        // worst case on purpose: timing must not leak whether a token was seen.
        private readonly double[] _connectTokenEntryTime = new double[MaxConnectTokenEntries];
        private readonly byte[] _connectTokenEntryMac = new byte[MaxConnectTokenEntries * Protocol.MacBytes];
        private readonly Address[] _connectTokenEntryAddress = new Address[MaxConnectTokenEntries];

        private readonly EncryptionManager _encryptionManager = new EncryptionManager();

        private readonly byte[] _receiveBuffer = new byte[Defines.MaxPacketBytes];
        private readonly byte[] _sendBuffer = new byte[Defines.MaxPacketBytes];
        private readonly NetworkSimulator.ReceiveHandler _simulatorReceiveHandler;
        private ulong _simulatorReceiveTimestamp;
        private bool _disposed;

        /// <summary>Create a server listening on <paramref name="serverAddress"/> (the public address clients connect to).</summary>
        public Server(string serverAddress, ServerConfig config, double time = 0.0)
            : this(serverAddress, null, config, time)
        {
        }

        /// <summary>
        /// Create a server. Dual form listens on one IPv4 and one IPv6 address.
        /// Mirrors netcode_server_create_dual; throws NetcodeException (with a
        /// ServerCreateError code) where the C library returns NULL.
        /// </summary>
        public Server(string serverAddress1, string? serverAddress2, ServerConfig config, double time)
        {
            ArgumentNullException.ThrowIfNull(config);
            if (config.PrivateKey == null || config.PrivateKey.Length != Protocol.KeyBytes)
                throw new ArgumentException($"config.PrivateKey must be {Protocol.KeyBytes} bytes", nameof(config));

            _config = config;
            config.PrivateKey.CopyTo(_privateKey.AsSpan());
            _simulatorReceiveHandler = ProcessPacketFromSimulator;

            // the overrides are called on the update path with no null check. a missing one is a
            // configuration error, refused here rather than dereferenced on the first update.
            if (_config.OverrideSendAndReceive && (_config.SendPacketOverride == null || _config.ReceivePacketOverride == null))
            {
                NetcodeLog.Error("error: override_send_and_receive requires both send_packet_override and receive_packet_override\n");
                throw new NetcodeException("override_send_and_receive requires both send_packet_override and receive_packet_override", (int)ServerCreateError.MissingOverrideCallback);
            }

            if (!Address.TryParse(serverAddress1, out Address address1))
            {
                NetcodeLog.Error("error: failed to parse server public address\n");
                throw new NetcodeException("failed to parse server public address", (int)ServerCreateError.ParseAddressFailed);
            }

            Address address2 = default;
            if (serverAddress2 != null && !Address.TryParse(serverAddress2, out address2))
            {
                NetcodeLog.Error("error: failed to parse server public address2\n");
                throw new NetcodeException("failed to parse server public address2", (int)ServerCreateError.ParseAddress2Failed);
            }

            if (address1.Type == AddressType.IPv4 || address2.Type == AddressType.IPv4)
            {
                Address bind = default;
                bind.Type = AddressType.IPv4;
                bind.Port = address1.Type == AddressType.IPv4 ? address1.Port : address2.Port;
                _socketIpv4 = CreateSocket(in bind);
            }

            if (address1.Type == AddressType.IPv6 || address2.Type == AddressType.IPv6)
            {
                Address bind = default;
                bind.Type = AddressType.IPv6;
                bind.Port = address1.Type == AddressType.IPv6 ? address1.Port : address2.Port;
                try
                {
                    _socketIpv6 = CreateSocket(in bind);
                }
                catch
                {
                    _socketIpv4?.Dispose();
                    throw;
                }
            }

            if (config.Simulator == null)
                NetcodeLog.Info($"server listening on {serverAddress1}\n");
            else
                NetcodeLog.Info($"server listening on {serverAddress1} (network simulator)\n");

            _address = address1;
            _address2 = address2;
            _time = time;
            _globalSequence = 1UL << 63;

            for (int i = 0; i < Protocol.MaxClients; i++)
            {
                _clientEncryptionIndex[i] = -1;
                _clientReplayProtection[i] = new ReplayProtection();
                _clientPacketQueue[i] = new PacketQueue();
            }

            ConnectTokenEntriesReset();
        }

        private NetcodeSocket? CreateSocket(in Address bind)
        {
            if (_config.Simulator != null || _config.OverrideSendAndReceive)
                return null;

            NetcodeSocket.CreateError error = NetcodeSocket.Create(in bind, Defines.SocketSndbufSize, Defines.SocketRcvbufSize, _config.EnablePacketTagging, out NetcodeSocket? socket);

            if (error == NetcodeSocket.CreateError.None)
                return socket;

            // report bind failures separately: a port already in use is the common
            // operational failure for dedicated servers
            ServerCreateError createError;
            if (error == NetcodeSocket.CreateError.BindFailed)
            {
                createError = bind.Type == AddressType.IPv6
                    ? ServerCreateError.BindSocketIpv6Failed
                    : ServerCreateError.BindSocketIpv4Failed;
            }
            else
            {
                createError = bind.Type == AddressType.IPv6
                    ? ServerCreateError.CreateSocketIpv6Failed
                    : ServerCreateError.CreateSocketIpv4Failed;
            }
            throw new NetcodeException($"failed to create server socket ({error})", (int)createError);
        }

        /// <summary>True between Start and Stop.</summary>
        public bool Running => _running;
        /// <summary>The number of client slots (0 when stopped).</summary>
        public int MaxClients => _maxClients;
        /// <summary>How many clients are currently connected.</summary>
        public int NumConnectedClients => _numConnectedClients;
        /// <summary>The time passed to the most recent Update.</summary>
        public double Time => _time;

        // for tests: the nonce-space invariant (global sequence re-seeded to 2^63 on every start)
        internal ulong GlobalSequence
        {
            get => _globalSequence;
            set => _globalSequence = value;
        }

        /// <summary>The port the server socket is bound to.</summary>
        public ushort Port =>
            _address.Type == AddressType.IPv4
                ? (_socketIpv4 != null ? _socketIpv4.Address.Port : _address.Port)
                : (_socketIpv6 != null ? _socketIpv6.Address.Port : _address.Port);

        /// <summary>Start the server with maxClients slots (1..Protocol.MaxClients). Logs and returns on out-of-range values.</summary>
        public void Start(int maxClients)
        {
            // the per-client arrays are sized MaxClients; an out of range value must not get through
            if (maxClients <= 0 || maxClients > Protocol.MaxClients)
            {
                NetcodeLog.Error($"error: max clients must be in [1,{Protocol.MaxClients}], got {maxClients}\n");
                return;
            }

            if (_running)
                Stop();

            NetcodeLog.Info($"server started with {maxClients} client slots\n");

            _running = true;
            _maxClients = maxClients;
            _numConnectedClients = 0;
            _challengeSequence = 0;
            Rng.GenerateKey(_challengeKey);

            // global packets (challenge, denied) encrypt with the same per-token server to
            // client keys as per-client packets, whose sequences start at zero, so the global
            // sequence lives in the top half of the sequence space to keep AEAD nonces
            // disjoint under a shared key. Stop() zeroes it, so it must be re-seeded on
            // every start — otherwise a stopped and restarted server would reuse nonces.
            _globalSequence = 1UL << 63;

            for (int i = 0; i < _maxClients; i++)
                _clientPacketQueue[i].Clear();

            for (int i = 0; i < Protocol.MaxClients; i++)
                _clientDisconnectReason[i] = DisconnectReason.None;
        }

        /// <summary>Stop the server, disconnecting every client.</summary>
        public void Stop()
        {
            if (!_running)
                return;

            DisconnectAllClients();

            // loopback clients are not disconnected above, but they must not survive a server stop
            for (int i = 0; i < _maxClients; i++)
            {
                if (_clientConnected[i] && _clientLoopback[i])
                    DisconnectLoopbackClient(i);
            }

            _running = false;
            _maxClients = 0;
            _numConnectedClients = 0;

            _globalSequence = 0;
            _challengeSequence = 0;
            Array.Clear(_challengeKey);

            ConnectTokenEntriesReset();

            _encryptionManager.Reset();

            NetcodeLog.Info("server stopped\n");
        }

        // --------------------------------------------------------------
        // connect token single-use history
        // --------------------------------------------------------------

        private void ConnectTokenEntriesReset()
        {
            for (int i = 0; i < MaxConnectTokenEntries; i++)
            {
                _connectTokenEntryTime[i] = -1000.0;
                _connectTokenEntryAddress[i] = default;
            }
            Array.Clear(_connectTokenEntryMac);
        }

        private bool ConnectTokenEntriesFindOrAdd(in Address address, ReadOnlySpan<byte> mac, double time)
        {
            // find the matching entry for the token mac and the oldest token entry.
            // constant time worst case. This is intentional!

            int matchingTokenIndex = -1;
            int oldestTokenIndex = -1;
            double oldestTokenTime = 0.0;

            for (int i = 0; i < MaxConnectTokenEntries; i++)
            {
                if (mac.SequenceEqual(_connectTokenEntryMac.AsSpan(i * Protocol.MacBytes, Protocol.MacBytes)))
                    matchingTokenIndex = i;

                if (oldestTokenIndex == -1 || _connectTokenEntryTime[i] < oldestTokenTime)
                {
                    oldestTokenTime = _connectTokenEntryTime[i];
                    oldestTokenIndex = i;
                }
            }

            // if no entry is found with the mac, this is a new connect token. replace the oldest.

            if (matchingTokenIndex == -1)
            {
                _connectTokenEntryTime[oldestTokenIndex] = time;
                _connectTokenEntryAddress[oldestTokenIndex] = address;
                mac.CopyTo(_connectTokenEntryMac.AsSpan(oldestTokenIndex * Protocol.MacBytes, Protocol.MacBytes));
                return true;
            }

            // allow connect tokens we have already seen from the same address

            if (_connectTokenEntryAddress[matchingTokenIndex].Equals(address))
                return true;

            return false;
        }

        // --------------------------------------------------------------
        // client lookup (flat linear scans — deliberate; see header comment)
        // --------------------------------------------------------------

        private int FindClientIndexById(ulong clientId)
        {
            for (int i = 0; i < _maxClients; i++)
            {
                if (_clientConnected[i] && _clientId[i] == clientId)
                    return i;
            }
            return -1;
        }

        private int FindClientIndexByAddress(in Address address)
        {
            for (int i = 0; i < _maxClients; i++)
            {
                if (_clientConnected[i] && _clientAddress[i].Equals(address))
                    return i;
            }
            return -1;
        }

        private int FindFreeClientIndex()
        {
            for (int i = 0; i < _maxClients; i++)
            {
                if (!_clientConnected[i])
                    return i;
            }
            return -1;
        }

        // --------------------------------------------------------------
        // sending
        // --------------------------------------------------------------

        private void SendGlobalPacket(int packetType, ReadOnlySpan<byte> packetData, in Address to, ReadOnlySpan<byte> packetKey)
        {
            int packetBytes = PacketIO.WriteEncryptedPacket(_sendBuffer, packetType, packetData, _globalSequence, packetKey, _config.ProtocolId);

            SendDispatch.SendPacketToAddress(
                _config.Simulator,
                _config.OverrideSendAndReceive ? _config.SendPacketOverride : null,
                _socketIpv4,
                _socketIpv6,
                in _address,
                in to,
                _sendBuffer.AsSpan(0, packetBytes));

            _globalSequence++;
        }

        private void SendClientPacket(int packetType, ReadOnlySpan<byte> packetData, int clientIndex)
        {
            if (!_encryptionManager.Touch(_clientEncryptionIndex[clientIndex], in _clientAddress[clientIndex], _time))
            {
                NetcodeLog.Error($"error: encryption mapping is out of date for client {clientIndex}\n");
                return;
            }

            ReadOnlySpan<byte> packetKey = _encryptionManager.GetSendKey(_clientEncryptionIndex[clientIndex]);

            int packetBytes = PacketIO.WriteEncryptedPacket(_sendBuffer, packetType, packetData, _clientSequence[clientIndex], packetKey, _config.ProtocolId);

            SendDispatch.SendPacketToAddress(
                _config.Simulator,
                _config.OverrideSendAndReceive ? _config.SendPacketOverride : null,
                _socketIpv4,
                _socketIpv6,
                in _address,
                in _clientAddress[clientIndex],
                _sendBuffer.AsSpan(0, packetBytes));

            _clientSequence[clientIndex]++;

            _clientLastPacketSendTime[clientIndex] = _time;
        }

        private void SendKeepAlive(int clientIndex)
        {
            Span<byte> data = stackalloc byte[8];
            BinaryPrimitives.WriteUInt32LittleEndian(data.Slice(0, 4), (uint)clientIndex);
            BinaryPrimitives.WriteUInt32LittleEndian(data.Slice(4, 4), (uint)_maxClients);
            SendClientPacket(PacketType.ConnectionKeepAlive, data, clientIndex);
        }

        // --------------------------------------------------------------
        // client slots
        // --------------------------------------------------------------

        private void ResetClientSlot(int clientIndex)
        {
            _clientPacketQueue[clientIndex].Clear();

            _clientConnected[clientIndex] = false;
            _clientLoopback[clientIndex] = false;
            _clientConfirmed[clientIndex] = false;
            _clientId[clientIndex] = 0;
            _clientSequence[clientIndex] = 0;
            _clientLastPacketSendTime[clientIndex] = 0.0;
            _clientLastPacketReceiveTime[clientIndex] = 0.0;
            _clientAddress[clientIndex] = default;
            _clientEncryptionIndex[clientIndex] = -1;
            _clientUserData.AsSpan(clientIndex * Protocol.UserDataBytes, Protocol.UserDataBytes).Clear();

            _numConnectedClients--;
        }

        private void DisconnectClientInternal(int clientIndex, bool sendDisconnectPackets, DisconnectReason disconnectReason)
        {
            NetcodeLog.Info($"server disconnected client {clientIndex}\n");

            // record why before the callback fires, so the reason can be queried from inside it
            _clientDisconnectReason[clientIndex] = disconnectReason;

            _config.OnClientConnectDisconnect?.Invoke(clientIndex, false);

            if (sendDisconnectPackets)
            {
                NetcodeLog.Debug($"server sent disconnect packets to client {clientIndex}\n");

                for (int i = 0; i < Defines.NumDisconnectPackets; i++)
                {
                    if (NetcodeLog.Enabled(LogLevel.Debug))
                        NetcodeLog.Debug($"server sent disconnect packet {i}\n");

                    SendClientPacket(PacketType.ConnectionDisconnect, ReadOnlySpan<byte>.Empty, clientIndex);
                }
            }

            _clientReplayProtection[clientIndex].Reset();

            _encryptionManager.ClientIndex[_clientEncryptionIndex[clientIndex]] = -1;

            _encryptionManager.RemoveEncryptionMapping(in _clientAddress[clientIndex], _time);

            ResetClientSlot(clientIndex);
        }

        /// <summary>Disconnect one client, sending redundant disconnect packets.</summary>
        public void DisconnectClient(int clientIndex)
        {
            if (!_running)
                return;

            if (clientIndex < 0 || clientIndex >= _maxClients)
                return;

            if (!_clientConnected[clientIndex])
                return;

            if (_clientLoopback[clientIndex])
                return;

            DisconnectClientInternal(clientIndex, sendDisconnectPackets: true, DisconnectReason.ServerDisconnect);
        }

        /// <summary>Disconnect every connected (non-loopback) client.</summary>
        public void DisconnectAllClients()
        {
            if (!_running)
                return;

            for (int i = 0; i < _maxClients; i++)
            {
                if (_clientConnected[i] && !_clientLoopback[i])
                    DisconnectClientInternal(i, sendDisconnectPackets: true, DisconnectReason.ServerDisconnect);
            }
        }

        private void ConnectClient(int clientIndex, in Address address, ulong clientId, int encryptionIndex, int timeoutSeconds, ReadOnlySpan<byte> userData)
        {
            _numConnectedClients++;

            _encryptionManager.SetExpireTime(encryptionIndex, -1.0);

            _encryptionManager.ClientIndex[encryptionIndex] = clientIndex;

            _clientConnected[clientIndex] = true;
            _clientTimeout[clientIndex] = timeoutSeconds;
            _clientEncryptionIndex[clientIndex] = encryptionIndex;
            _clientId[clientIndex] = clientId;
            _clientSequence[clientIndex] = 0;
            _clientAddress[clientIndex] = address;
            _clientDisconnectReason[clientIndex] = DisconnectReason.None;

            _clientLastPacketSendTime[clientIndex] = _time;
            _clientLastPacketReceiveTime[clientIndex] = _time;
            userData.CopyTo(_clientUserData.AsSpan(clientIndex * Protocol.UserDataBytes, Protocol.UserDataBytes));

            if (NetcodeLog.Enabled(LogLevel.Info))
                NetcodeLog.Info($"server accepted client {address} {clientId:x16} in slot {clientIndex}\n");

            SendKeepAlive(clientIndex);

            _config.OnClientConnectDisconnect?.Invoke(clientIndex, true);
        }

        // --------------------------------------------------------------
        // packet processing
        // --------------------------------------------------------------

        private void ProcessConnectionRequestPacket(in Address from, Span<byte> decryptedToken)
        {
            var connectTokenPrivate = new ConnectTokenPrivate();
            if (!connectTokenPrivate.Read(decryptedToken))
            {
                NetcodeLog.Debug("server ignored connection request. failed to read connect token\n");
                return;
            }

            bool foundServerAddress = false;
            for (int i = 0; i < connectTokenPrivate.NumServerAddresses; i++)
            {
                if (_address.Equals(connectTokenPrivate.ServerAddresses[i]))
                    foundServerAddress = true;
                if (_address2.Type != AddressType.None && _address2.Equals(connectTokenPrivate.ServerAddresses[i]))
                    foundServerAddress = true;
            }
            if (!foundServerAddress)
            {
                NetcodeLog.Debug("server ignored connection request. server address not in connect token whitelist\n");
                return;
            }

            if (FindClientIndexByAddress(in from) != -1)
            {
                NetcodeLog.Debug("server ignored connection request. a client with this address is already connected\n");
                return;
            }

            if (FindClientIndexById(connectTokenPrivate.ClientId) != -1)
            {
                NetcodeLog.Debug("server ignored connection request. a client with this id is already connected\n");
                return;
            }

            // the private token's HMAC survives in-place decryption in the last 16 bytes
            if (!ConnectTokenEntriesFindOrAdd(
                    in from,
                    decryptedToken.Slice(Defines.ConnectTokenPrivateBytes - Protocol.MacBytes, Protocol.MacBytes),
                    _time))
            {
                NetcodeLog.Debug("server ignored connection request. connect token has already been used\n");
                return;
            }

            if (_numConnectedClients == _maxClients)
            {
                NetcodeLog.Debug("server denied connection request. server is full\n");
                SendGlobalPacket(PacketType.ConnectionDenied, ReadOnlySpan<byte>.Empty, in from, connectTokenPrivate.ServerToClientKey);
                return;
            }

            double expireTime = connectTokenPrivate.TimeoutSeconds >= 0 ? _time + connectTokenPrivate.TimeoutSeconds : -1.0;

            if (!_encryptionManager.AddEncryptionMapping(
                    in from,
                    connectTokenPrivate.ServerToClientKey,
                    connectTokenPrivate.ClientToServerKey,
                    _time,
                    expireTime,
                    connectTokenPrivate.TimeoutSeconds))
            {
                NetcodeLog.Debug("server ignored connection request. failed to add encryption mapping\n");
                return;
            }

            Span<byte> challengePacketData = stackalloc byte[8 + Defines.ChallengeTokenBytes];
            BinaryPrimitives.WriteUInt64LittleEndian(challengePacketData.Slice(0, 8), _challengeSequence);

            Span<byte> challengeTokenBuffer = challengePacketData.Slice(8, Defines.ChallengeTokenBytes);
            challengeTokenBuffer.Clear();
            {
                var writer = new ByteWriter(challengeTokenBuffer);
                writer.U64(connectTokenPrivate.ClientId);
                writer.Bytes(connectTokenPrivate.UserData);
            }
            ChallengeToken.Encrypt(challengeTokenBuffer, _challengeSequence, _challengeKey);

            _challengeSequence++;

            NetcodeLog.Debug("server sent connection challenge packet\n");

            SendGlobalPacket(PacketType.ConnectionChallenge, challengePacketData, in from, connectTokenPrivate.ServerToClientKey);
        }

        private void ProcessConnectionResponsePacket(in Address from, Span<byte> packetData, int encryptionIndex)
        {
            ulong challengeTokenSequence = BinaryPrimitives.ReadUInt64LittleEndian(packetData.Slice(0, 8));
            Span<byte> challengeTokenBuffer = packetData.Slice(8, Defines.ChallengeTokenBytes);

            if (!ChallengeToken.Decrypt(challengeTokenBuffer, challengeTokenSequence, _challengeKey))
            {
                NetcodeLog.Debug("server ignored connection response. failed to decrypt challenge token\n");
                return;
            }

            var challengeReader = new ByteReader(challengeTokenBuffer);
            ulong challengeClientId = challengeReader.U64();
            ReadOnlySpan<byte> challengeUserData = challengeTokenBuffer.Slice(8, Protocol.UserDataBytes);

            ReadOnlySpan<byte> packetSendKey = _encryptionManager.GetSendKey(encryptionIndex);

            if (packetSendKey.Length == 0)
            {
                NetcodeLog.Debug("server ignored connection response. no packet send key\n");
                return;
            }

            if (FindClientIndexByAddress(in from) != -1)
            {
                NetcodeLog.Debug("server ignored connection response. a client with this address is already connected\n");
                return;
            }

            if (FindClientIndexById(challengeClientId) != -1)
            {
                NetcodeLog.Debug("server ignored connection response. a client with this id is already connected\n");
                return;
            }

            if (_numConnectedClients == _maxClients)
            {
                NetcodeLog.Debug("server denied connection response. server is full\n");
                SendGlobalPacket(PacketType.ConnectionDenied, ReadOnlySpan<byte>.Empty, in from, packetSendKey);
                return;
            }

            int clientIndex = FindFreeClientIndex();

            int timeoutSeconds = _encryptionManager.GetTimeout(encryptionIndex);

            ConnectClient(clientIndex, in from, challengeClientId, encryptionIndex, timeoutSeconds, challengeUserData);
        }

        private void ProcessPacketInternal(in Address from, in ReadPacketResult packet, Span<byte> buffer, int encryptionIndex, int clientIndex)
        {
            switch (packet.Type)
            {
                case PacketType.ConnectionRequest:
                {
                    if ((Flags & FlagIgnoreConnectionRequestPackets) == 0)
                    {
                        if (NetcodeLog.Enabled(LogLevel.Debug))
                            NetcodeLog.Debug($"server received connection request from {from}\n");
                        ProcessConnectionRequestPacket(in from, buffer.Slice(packet.DataOffset, packet.DataLength));
                    }
                }
                break;

                case PacketType.ConnectionResponse:
                {
                    if ((Flags & FlagIgnoreConnectionResponsePackets) == 0)
                    {
                        if (NetcodeLog.Enabled(LogLevel.Debug))
                            NetcodeLog.Debug($"server received connection response from {from}\n");
                        ProcessConnectionResponsePacket(in from, buffer.Slice(packet.DataOffset, packet.DataLength), encryptionIndex);
                    }
                }
                break;

                case PacketType.ConnectionKeepAlive:
                {
                    if (clientIndex != -1)
                    {
                        if (NetcodeLog.Enabled(LogLevel.Debug))
                            NetcodeLog.Debug($"server received connection keep alive packet from client {clientIndex}\n");
                        _clientLastPacketReceiveTime[clientIndex] = _time;
                        if (!_clientConfirmed[clientIndex])
                        {
                            if (NetcodeLog.Enabled(LogLevel.Debug))
                                NetcodeLog.Debug($"server confirmed connection with client {clientIndex}\n");
                            _clientConfirmed[clientIndex] = true;
                        }
                    }
                }
                break;

                case PacketType.ConnectionPayload:
                {
                    if (clientIndex != -1)
                    {
                        if (NetcodeLog.Enabled(LogLevel.Debug))
                            NetcodeLog.Debug($"server received connection payload packet from client {clientIndex}\n");
                        _clientLastPacketReceiveTime[clientIndex] = _time;
                        if (!_clientConfirmed[clientIndex])
                        {
                            if (NetcodeLog.Enabled(LogLevel.Debug))
                                NetcodeLog.Debug($"server confirmed connection with client {clientIndex}\n");
                            _clientConfirmed[clientIndex] = true;
                        }
                        _clientPacketQueue[clientIndex].Push(buffer.Slice(packet.DataOffset, packet.DataLength), packet.Sequence);
                    }
                }
                break;

                case PacketType.ConnectionDisconnect:
                {
                    if (clientIndex != -1)
                    {
                        if (NetcodeLog.Enabled(LogLevel.Debug))
                            NetcodeLog.Debug($"server received disconnect packet from client {clientIndex}\n");
                        DisconnectClientInternal(clientIndex, sendDisconnectPackets: false, DisconnectReason.ClientDisconnect);
                    }
                }
                break;

                default:
                    break;
            }
        }

        private void ReadAndProcessPacket(in Address from, Span<byte> packetData, ulong currentTimestamp)
        {
            if (!_running)
                return;

            if (packetData.Length <= 1)
                return;

            int encryptionIndex;
            int clientIndex = FindClientIndexByAddress(in from);
            if (clientIndex != -1)
            {
                encryptionIndex = _clientEncryptionIndex[clientIndex];
            }
            else
            {
                encryptionIndex = _encryptionManager.FindEncryptionMapping(in from, _time);
            }

            ReadOnlySpan<byte> readPacketKey = _encryptionManager.GetReceiveKey(encryptionIndex);

            if (readPacketKey.Length == 0 && packetData[0] != 0)
            {
                if (NetcodeLog.Enabled(LogLevel.Debug))
                    NetcodeLog.Debug($"server could not process packet because no encryption mapping exists for {from}\n");
                return;
            }

            ReadPacketResult packet = PacketIO.ReadPacket(
                packetData,
                hasReadPacketKey: readPacketKey.Length != 0,
                readPacketKey,
                _config.ProtocolId,
                currentTimestamp,
                hasPrivateKey: true,
                _privateKey,
                AllowedPackets,
                clientIndex != -1 ? _clientReplayProtection[clientIndex] : null);

            if (packet.Type < 0)
                return;

            ProcessPacketInternal(in from, in packet, packetData, encryptionIndex, clientIndex);
        }

        /// <summary>
        /// Process a raw packet received for this server from an external socket
        /// architecture. Mirrors netcode_server_process_packet.
        /// </summary>
        public void ProcessPacket(in Address from, Span<byte> packetData)
        {
            ulong currentTimestamp = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            ReadAndProcessPacket(in from, packetData, currentTimestamp);
        }

        private void ProcessPacketFromSimulator(in Address from, ReadOnlySpan<byte> packetData)
        {
            Span<byte> buffer = _receiveBuffer.AsSpan(0, packetData.Length);
            packetData.CopyTo(buffer);
            ReadAndProcessPacket(in from, buffer, _simulatorReceiveTimestamp);
        }

        private void ReceivePackets()
        {
            ulong currentTimestamp = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            if (_config.Simulator == null)
            {
                while (true)
                {
                    Address from = default;
                    int packetBytes = 0;

                    if (_config.OverrideSendAndReceive)
                    {
                        packetBytes = _config.ReceivePacketOverride!(ref from, _receiveBuffer);
                    }
                    else
                    {
                        if (_socketIpv4 != null)
                            packetBytes = _socketIpv4.ReceivePacket(ref from, _receiveBuffer);

                        if (packetBytes == 0 && _socketIpv6 != null)
                            packetBytes = _socketIpv6.ReceivePacket(ref from, _receiveBuffer);
                    }

                    if (packetBytes == 0)
                        break;

                    ReadAndProcessPacket(in from, _receiveBuffer.AsSpan(0, packetBytes), currentTimestamp);
                }
            }
            else
            {
                _simulatorReceiveTimestamp = currentTimestamp;
                _config.Simulator.ReceivePackets(in _address, Defines.ServerMaxReceivePackets, _simulatorReceiveHandler);
            }
        }

        private void SendPackets()
        {
            if (!_running)
                return;

            for (int i = 0; i < _maxClients; i++)
            {
                if (_clientConnected[i] && !_clientLoopback[i] &&
                    _clientLastPacketSendTime[i] + (1.0 / Defines.PacketSendRate) <= _time)
                {
                    if (NetcodeLog.Enabled(LogLevel.Debug))
                        NetcodeLog.Debug($"server sent connection keep alive packet to client {i}\n");
                    SendKeepAlive(i);
                }
            }
        }

        private void CheckForTimeouts()
        {
            if (!_running)
                return;

            for (int i = 0; i < _maxClients; i++)
            {
                if (!_clientConnected[i])
                    continue;

                if (_clientTimeout[i] <= 0)
                    continue;

                if (_clientLoopback[i])
                    continue;

                if (_clientLastPacketReceiveTime[i] + _clientTimeout[i] <= _time)
                {
                    NetcodeLog.Info($"server timed out client {i}\n");
                    DisconnectClientInternal(i, sendDisconnectPackets: false, DisconnectReason.TimedOut);
                }
            }
        }

        /// <summary>Advance the server: receive and process packets, send keep-alives, run timeouts. Call every frame.</summary>
        public void Update(double time)
        {
            _time = time;
            ReceivePackets();
            SendPackets();
            CheckForTimeouts();
        }

        // --------------------------------------------------------------
        // public per-client accessors
        // --------------------------------------------------------------

        /// <summary>Is a client connected in this slot?</summary>
        public bool ClientConnected(int clientIndex)
        {
            if (!_running)
                return false;
            if (clientIndex < 0 || clientIndex >= _maxClients)
                return false;
            return _clientConnected[clientIndex];
        }

        /// <summary>Why the client in this slot was last disconnected (queryable from inside the disconnect callback).</summary>
        public DisconnectReason ClientDisconnectReason(int clientIndex)
        {
            if (!_running)
                return DisconnectReason.None;
            if (clientIndex < 0 || clientIndex >= _maxClients)
                return DisconnectReason.None;
            return _clientDisconnectReason[clientIndex];
        }

        /// <summary>The globally unique id of the client in this slot (0 when empty).</summary>
        public ulong ClientId(int clientIndex)
        {
            if (!_running)
                return 0;
            if (clientIndex < 0 || clientIndex >= _maxClients)
                return 0;
            return _clientId[clientIndex];
        }

        /// <summary>The address of the client in this slot (default when empty).</summary>
        public Address ClientAddress(int clientIndex)
        {
            if (!_running)
                return default;
            if (clientIndex < 0 || clientIndex >= _maxClients)
                return default;
            return _clientAddress[clientIndex];
        }

        /// <summary>The sequence number of the next packet the server will send to this client.</summary>
        public ulong NextPacketSequence(int clientIndex)
        {
            if (!_running)
                return 0;
            if (clientIndex < 0 || clientIndex >= _maxClients)
                return 0;
            if (!_clientConnected[clientIndex])
                return 0;
            return _clientSequence[clientIndex];
        }

        /// <summary>The 256 bytes of user data carried in the client's connect token.</summary>
        public ReadOnlySpan<byte> ClientUserData(int clientIndex)
        {
            if (!_running)
                return ReadOnlySpan<byte>.Empty;
            if (clientIndex < 0 || clientIndex >= _maxClients)
                return ReadOnlySpan<byte>.Empty;
            return _clientUserData.AsSpan(clientIndex * Protocol.UserDataBytes, Protocol.UserDataBytes);
        }

        /// <summary>Send a payload (1..MaxPacketSize bytes) to a connected client.</summary>
        public void SendPacket(int clientIndex, ReadOnlySpan<byte> packetData)
        {
            // zero byte payloads are not valid on the wire and would silently vanish at the receiver
            if (packetData.Length <= 0 || packetData.Length > Protocol.MaxPacketSize)
            {
                NetcodeLog.Error($"error: payload packet size is out of range ({packetData.Length})\n");
                return;
            }

            if (!_running)
                return;

            if (clientIndex < 0 || clientIndex >= _maxClients)
                return;

            if (!_clientConnected[clientIndex])
                return;

            if (!_clientLoopback[clientIndex])
            {
                // while unconfirmed, prefix each payload with a keep-alive so the client
                // learns its client index and max clients
                if (!_clientConfirmed[clientIndex])
                    SendKeepAlive(clientIndex);

                SendClientPacket(PacketType.ConnectionPayload, packetData, clientIndex);
            }
            else
            {
                _config.SendLoopbackPacket!(clientIndex, packetData, _clientSequence[clientIndex]++);
                _clientLastPacketSendTime[clientIndex] = _time;
            }
        }

        /// <summary>
        /// Pop the oldest received payload from a client into <paramref name="payload"/>
        /// (must be at least MaxPacketSize bytes). Returns the payload length, or -1
        /// when no packet is queued.
        /// </summary>
        public int ReceivePacket(int clientIndex, Span<byte> payload, out ulong sequence)
        {
            sequence = 0;

            if (!_running)
                return -1;

            if (clientIndex < 0 || clientIndex >= _maxClients)
                return -1;

            if (!_clientConnected[clientIndex])
                return -1;

            return _clientPacketQueue[clientIndex].Pop(payload, out sequence);
        }

        // --------------------------------------------------------------
        // loopback
        // --------------------------------------------------------------

        /// <summary>Attach a loopback client to a slot: payloads flow through the loopback callbacks, no networking.</summary>
        public void ConnectLoopbackClient(int clientIndex, ulong clientId, ReadOnlySpan<byte> userData)
        {
            // the server sends to a loopback client only through this callback. without it the
            // first send would call a null pointer, so refuse the slot at all, in every build.
            if (_config.SendLoopbackPacket == null)
            {
                NetcodeLog.Error("error: a loopback client requires send_loopback_packet_callback\n");
                return;
            }

            if (!_running)
                return;

            if (clientIndex < 0 || clientIndex >= _maxClients)
                return;

            if (_clientConnected[clientIndex])
                return;

            _numConnectedClients++;

            _clientLoopback[clientIndex] = true;
            _clientConnected[clientIndex] = true;
            _clientConfirmed[clientIndex] = true;
            _clientEncryptionIndex[clientIndex] = -1;
            _clientId[clientIndex] = clientId;
            _clientSequence[clientIndex] = 0;
            _clientDisconnectReason[clientIndex] = DisconnectReason.None;
            _clientAddress[clientIndex] = default;
            _clientLastPacketSendTime[clientIndex] = _time;
            _clientLastPacketReceiveTime[clientIndex] = _time;

            Span<byte> slot = _clientUserData.AsSpan(clientIndex * Protocol.UserDataBytes, Protocol.UserDataBytes);
            if (userData.Length > 0)
                userData.CopyTo(slot);
            else
                slot.Clear();

            if (NetcodeLog.Enabled(LogLevel.Info))
                NetcodeLog.Info($"server connected loopback client {clientId:x16} in slot {clientIndex}\n");

            _config.OnClientConnectDisconnect?.Invoke(clientIndex, true);
        }

        /// <summary>Detach a loopback client from its slot.</summary>
        public void DisconnectLoopbackClient(int clientIndex)
        {
            if (!_running)
                return;

            if (clientIndex < 0 || clientIndex >= _maxClients)
                return;

            if (!_clientConnected[clientIndex] || !_clientLoopback[clientIndex])
                return;

            NetcodeLog.Info($"server disconnected loopback client {clientIndex}\n");

            _clientDisconnectReason[clientIndex] = DisconnectReason.ServerDisconnect;

            _config.OnClientConnectDisconnect?.Invoke(clientIndex, false);

            ResetClientSlot(clientIndex);
        }

        /// <summary>Is the client in this slot a loopback client?</summary>
        public bool ClientLoopback(int clientIndex)
        {
            if (!_running)
                return false;
            if (clientIndex < 0 || clientIndex >= _maxClients)
                return false;
            return _clientLoopback[clientIndex];
        }

        /// <summary>Deliver a payload from a loopback client (the client side of the loopback pair calls this).</summary>
        public void ProcessLoopbackPacket(int clientIndex, ReadOnlySpan<byte> packetData, ulong packetSequence)
        {
            if (!_running)
                return;

            if (clientIndex < 0 || clientIndex >= _maxClients)
                return;

            if (!_clientConnected[clientIndex] || !_clientLoopback[clientIndex])
                return;

            if (packetData.Length <= 0 || packetData.Length > Protocol.MaxPacketSize)
                return;

            if (NetcodeLog.Enabled(LogLevel.Debug))
                NetcodeLog.Debug($"server processing loopback packet from client {clientIndex}\n");

            _clientLastPacketReceiveTime[clientIndex] = _time;

            _clientPacketQueue[clientIndex].Push(packetData, packetSequence);
        }

        /// <summary>Stop (if running) and release the sockets.</summary>
        public void Dispose()
        {
            if (_disposed)
                return;
            _disposed = true;
            Stop();
            _socketIpv4?.Dispose();
            _socketIpv6?.Dispose();
        }
    }
}
