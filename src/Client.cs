/*
    Client.cs — the netcode client state machine (netcode_client_t).

    Same update-loop model as the C library: call Update(time) every frame.
    States and transitions are ported line-for-line from netcode.c.

    Copyright © 2026 Más Bandwidth LLC. Licensed under AGPL-3.0 (see LICENSE).
*/

using System;

namespace Netcode
{
    /// <summary>Client states. Negative values are error states; the goal state is Connected.
    /// Same numeric values as the C library (NETCODE_CLIENT_STATE_*).</summary>
    public enum ClientState
    {
        /// <summary>The connect token expired before a connection was established.</summary>
        ConnectTokenExpired = -6,
        /// <summary>The connect token passed to Connect was invalid.</summary>
        InvalidConnectToken = -5,
        /// <summary>An established connection timed out.</summary>
        ConnectionTimedOut = -4,
        /// <summary>No keep-alive arrived while sending connection responses.</summary>
        ConnectionResponseTimedOut = -3,
        /// <summary>No challenge arrived while sending connection requests.</summary>
        ConnectionRequestTimedOut = -2,
        /// <summary>The server denied the connection (usually: server full).</summary>
        ConnectionDenied = -1,
        /// <summary>Not connected. The initial state.</summary>
        Disconnected = 0,
        /// <summary>Sending connection request packets to the server.</summary>
        SendingConnectionRequest = 1,
        /// <summary>Sending connection response packets to the server.</summary>
        SendingConnectionResponse = 2,
        /// <summary>Connected to the server.</summary>
        Connected = 3,
    }

    /// <summary>Why client creation failed (carried by NetcodeException.ErrorCode).</summary>
    public enum ClientCreateError
    {
        /// <summary>No error.</summary>
        None = 0,
        /// <summary>The bind address failed to parse.</summary>
        ParseAddressFailed = 1,
        /// <summary>The second bind address failed to parse.</summary>
        ParseAddress2Failed = 2,
        /// <summary>A network simulator client must bind to a specific port.</summary>
        SimulatorRequiresPort = 3,
        /// <summary>The IPv4 socket could not be created or bound.</summary>
        CreateSocketIpv4Failed = 4,
        /// <summary>The IPv6 socket could not be created or bound.</summary>
        CreateSocketIpv6Failed = 5,
        /// <summary>OverrideSendAndReceive was set without both override callbacks.</summary>
        MissingOverrideCallback = 7,
    }

    /// <summary>Thrown when a Client or Server cannot be created (bad bind address, socket failure).</summary>
    public sealed class NetcodeException : Exception
    {
        /// <summary>A ClientCreateError or ServerCreateError value, depending on which endpoint threw.</summary>
        public int ErrorCode { get; }

        /// <summary>Create an exception carrying a create-error code.</summary>
        public NetcodeException(string message, int errorCode) : base(message)
        {
            ErrorCode = errorCode;
        }
    }

    /// <summary>Client configuration. Mirrors netcode_client_config_t.</summary>
    public sealed class ClientConfig
    {
        /// <summary>Route packets through a deterministic network simulator instead of sockets.</summary>
        public NetworkSimulator? Simulator;
        /// <summary>Called on every state transition with (oldState, newState).</summary>
        public Action<ClientState, ClientState>? OnStateChange;
        /// <summary>Called to deliver payloads when the client is in loopback mode.</summary>
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
    /// The netcode client. Non-blocking, update-loop driven: create it, call
    /// Connect with a connect token from the backend, then call Update(time)
    /// every frame and poll State / ReceivePacket.
    /// </summary>
    public sealed class Client : IDisposable
    {
        private static readonly bool[] AllowedPackets = BuildAllowedPackets();

        private static bool[] BuildAllowedPackets()
        {
            var allowed = new bool[PacketType.NumPackets];
            allowed[PacketType.ConnectionDenied] = true;
            allowed[PacketType.ConnectionChallenge] = true;
            allowed[PacketType.ConnectionKeepAlive] = true;
            allowed[PacketType.ConnectionPayload] = true;
            allowed[PacketType.ConnectionDisconnect] = true;
            return allowed;
        }

        private readonly ClientConfig _config;
        private ClientState _state;
        private double _time;
        private double _connectStartTime;
        private double _lastPacketSendTime;
        private double _lastPacketReceiveTime;
        private bool _shouldDisconnect;
        private ClientState _shouldDisconnectState;
        private ulong _sequence;
        private int _clientIndex;
        private int _maxClients;
        private int _serverAddressIndex;
        private Address _address;
        private Address _serverAddress;
        private readonly ConnectTokenData _connectToken = new ConnectTokenData();
        private NetcodeSocket? _socketIpv4;
        private NetcodeSocket? _socketIpv6;
        private readonly byte[] _writePacketKey = new byte[Protocol.KeyBytes];
        private readonly byte[] _readPacketKey = new byte[Protocol.KeyBytes];
        private readonly ReplayProtection _replayProtection = new ReplayProtection();
        private readonly PacketQueue _packetReceiveQueue = new PacketQueue();
        private ulong _challengeTokenSequence;
        private readonly byte[] _challengeTokenData = new byte[Defines.ChallengeTokenBytes];
        private bool _loopback;
        private bool _disposed;

        private readonly byte[] _receiveBuffer = new byte[Defines.MaxPacketBytes];
        private readonly byte[] _sendBuffer = new byte[Defines.MaxPacketBytes];
        private readonly NetworkSimulator.ReceiveHandler _simulatorReceiveHandler;

        /// <summary>Create a client bound to <paramref name="bindAddress"/> (use port 0 to let the OS pick).</summary>
        public Client(string bindAddress, ClientConfig? config = null, double time = 0.0)
            : this(bindAddress, null, config, time)
        {
        }

        /// <summary>
        /// Create a client. Dual form binds one IPv4 and one IPv6 socket so the
        /// client can connect to servers of either family. Mirrors
        /// netcode_client_create_dual; throws NetcodeException (with a
        /// ClientCreateError code) where the C library returns NULL.
        /// </summary>
        public Client(string bindAddress1, string? bindAddress2, ClientConfig? config, double time)
        {
            _config = config ?? new ClientConfig();
            _simulatorReceiveHandler = ProcessPacketFromSimulator;

            if (!Address.TryParse(bindAddress1, out Address address1))
            {
                NetcodeLog.Error("error: failed to parse client address\n");
                throw new NetcodeException("failed to parse client address", (int)ClientCreateError.ParseAddressFailed);
            }

            Address address2 = default;
            if (bindAddress2 != null && !Address.TryParse(bindAddress2, out address2))
            {
                NetcodeLog.Error("error: failed to parse client address2\n");
                throw new NetcodeException("failed to parse client address2", (int)ClientCreateError.ParseAddress2Failed);
            }

            if (address1.Type == AddressType.IPv4 || address2.Type == AddressType.IPv4)
            {
                Address bind = address1.Type == AddressType.IPv4 ? address1 : address2;
                _socketIpv4 = CreateSocket(in bind, ClientCreateError.CreateSocketIpv4Failed);
            }

            if (address1.Type == AddressType.IPv6 || address2.Type == AddressType.IPv6)
            {
                Address bind = address1.Type == AddressType.IPv6 ? address1 : address2;
                try
                {
                    _socketIpv6 = CreateSocket(in bind, ClientCreateError.CreateSocketIpv6Failed);
                }
                catch
                {
                    _socketIpv4?.Dispose();
                    throw;
                }
            }

            Address socketAddress = address1.Type == AddressType.IPv4
                ? (_socketIpv4 != null ? _socketIpv4.Address : address1)
                : (_socketIpv6 != null ? _socketIpv6.Address : address1);

            if (_config.Simulator == null)
                NetcodeLog.Info($"client started on port {socketAddress.Port}\n");
            else
                NetcodeLog.Info($"client started on port {socketAddress.Port} (network simulator)\n");

            _address = _config.Simulator != null ? address1 : socketAddress;
            _state = ClientState.Disconnected;
            _time = time;
            _lastPacketSendTime = -1000.0;
            _lastPacketReceiveTime = -1000.0;
            _shouldDisconnectState = ClientState.Disconnected;
        }

        private NetcodeSocket? CreateSocket(in Address bind, ClientCreateError socketError)
        {
            if (_config.Simulator == null)
            {
                if (!_config.OverrideSendAndReceive)
                {
                    NetcodeSocket.CreateError error = NetcodeSocket.Create(in bind, Defines.SocketSndbufSize, Defines.SocketRcvbufSize, _config.EnablePacketTagging, out NetcodeSocket? socket);
                    if (error != NetcodeSocket.CreateError.None)
                        throw new NetcodeException($"failed to create client socket ({error})", (int)socketError);
                    return socket;
                }
                return null;
            }
            else
            {
                if (bind.Port == 0)
                {
                    NetcodeLog.Error("error: must bind to a specific port when using network simulator\n");
                    throw new NetcodeException("must bind to a specific port when using network simulator", (int)ClientCreateError.SimulatorRequiresPort);
                }
                return null;
            }
        }

        /// <summary>Current client state.</summary>
        public ClientState State => _state;
        /// <summary>The slot index assigned by the server (valid while connected).</summary>
        public int ClientIndex => _clientIndex;
        /// <summary>The server's max clients (valid while connected).</summary>
        public int MaxClients => _maxClients;
        /// <summary>True when connected via loopback rather than the network.</summary>
        public bool IsLoopback => _loopback;
        /// <summary>The sequence number of the next packet this client will send.</summary>
        public ulong NextPacketSequence => _sequence;
        /// <summary>The server address the client is connecting or connected to.</summary>
        public Address ServerAddress => _serverAddress;

        /// <summary>The port the client socket is bound to.</summary>
        public ushort Port =>
            _address.Type == AddressType.IPv4
                ? (_socketIpv4 != null ? _socketIpv4.Address.Port : _address.Port)
                : (_socketIpv6 != null ? _socketIpv6.Address.Port : _address.Port);

        private void SetState(ClientState state)
        {
            if (NetcodeLog.Enabled(LogLevel.Debug))
                NetcodeLog.Debug($"client changed state from '{StateName(_state)}' to '{StateName(state)}'\n");

            _config.OnStateChange?.Invoke(_state, state);

            _state = state;
        }

        /// <summary>Human-readable name for a client state (matches the C library's strings).</summary>
        public static string StateName(ClientState state) => state switch
        {
            ClientState.ConnectTokenExpired => "connect token expired",
            ClientState.InvalidConnectToken => "invalid connect token",
            ClientState.ConnectionTimedOut => "connection timed out",
            ClientState.ConnectionRequestTimedOut => "connection request timed out",
            ClientState.ConnectionResponseTimedOut => "connection response timed out",
            ClientState.ConnectionDenied => "connection denied",
            ClientState.Disconnected => "disconnected",
            ClientState.SendingConnectionRequest => "sending connection request",
            ClientState.SendingConnectionResponse => "sending connection response",
            ClientState.Connected => "connected",
            _ => "???",
        };

        private void ResetBeforeNextConnect()
        {
            _connectStartTime = _time;
            _lastPacketSendTime = _time - 1.0;
            _lastPacketReceiveTime = _time;
            _shouldDisconnect = false;
            _shouldDisconnectState = ClientState.Disconnected;
            _challengeTokenSequence = 0;

            Array.Clear(_challengeTokenData);

            _replayProtection.Reset();
        }

        private void ResetConnectionData(ClientState clientState)
        {
            _sequence = 0;
            _loopback = false;
            _clientIndex = 0;
            _maxClients = 0;
            _connectStartTime = 0.0;
            _serverAddressIndex = 0;
            _serverAddress = default;
            ClearConnectToken();
            Array.Clear(_writePacketKey);
            Array.Clear(_readPacketKey);

            SetState(clientState);

            ResetBeforeNextConnect();

            _packetReceiveQueue.Clear();
        }

        private void ClearConnectToken()
        {
            _connectToken.ProtocolId = 0;
            _connectToken.CreateTimestamp = 0;
            _connectToken.ExpireTimestamp = 0;
            _connectToken.TimeoutSeconds = 0;
            _connectToken.NumServerAddresses = 0;
            Array.Clear(_connectToken.VersionInfo);
            Array.Clear(_connectToken.Nonce);
            Array.Clear(_connectToken.PrivateData);
            Array.Clear(_connectToken.ClientToServerKey);
            Array.Clear(_connectToken.ServerToClientKey);
            Array.Clear(_connectToken.ServerAddresses);
        }

        /// <summary>
        /// Begin connecting with a 2048-byte connect token obtained from the backend.
        /// On an invalid token the client transitions to InvalidConnectToken (no throw).
        /// </summary>
        public void Connect(ReadOnlySpan<byte> connectToken)
        {
            Disconnect();

            if (!_connectToken.Read(connectToken))
            {
                SetState(ClientState.InvalidConnectToken);
                return;
            }

            _serverAddressIndex = 0;
            _serverAddress = _connectToken.ServerAddresses[0];

            if (NetcodeLog.Enabled(LogLevel.Info))
            {
                if (_connectToken.NumServerAddresses == 1)
                    NetcodeLog.Info($"client connecting to server {_serverAddress}\n");
                else
                    NetcodeLog.Info($"client connecting to server {_serverAddress} [{_serverAddressIndex + 1}/{_connectToken.NumServerAddresses}]\n");
            }

            _connectToken.ServerToClientKey.CopyTo(_readPacketKey.AsSpan());
            _connectToken.ClientToServerKey.CopyTo(_writePacketKey.AsSpan());

            ResetBeforeNextConnect();

            SetState(ClientState.SendingConnectionRequest);
        }

        // --------------------------------------------------------------
        // packet processing
        // --------------------------------------------------------------

        private void ProcessPacketInternal(in Address from, in ReadPacketResult packet, ReadOnlySpan<byte> buffer)
        {
            switch (packet.Type)
            {
                case PacketType.ConnectionDenied:
                {
                    if ((_state == ClientState.SendingConnectionRequest ||
                         _state == ClientState.SendingConnectionResponse)
                        && from.Equals(_serverAddress))
                    {
                        _shouldDisconnect = true;
                        _shouldDisconnectState = ClientState.ConnectionDenied;
                        _lastPacketReceiveTime = _time;
                    }
                }
                break;

                case PacketType.ConnectionChallenge:
                {
                    if (_state == ClientState.SendingConnectionRequest && from.Equals(_serverAddress))
                    {
                        NetcodeLog.Debug("client received connection challenge packet from server\n");

                        ReadOnlySpan<byte> data = buffer.Slice(packet.DataOffset, packet.DataLength);
                        _challengeTokenSequence = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(0, 8));
                        data.Slice(8, Defines.ChallengeTokenBytes).CopyTo(_challengeTokenData);
                        _lastPacketReceiveTime = _time;

                        SetState(ClientState.SendingConnectionResponse);
                    }
                }
                break;

                case PacketType.ConnectionKeepAlive:
                {
                    if (from.Equals(_serverAddress))
                    {
                        ReadOnlySpan<byte> data = buffer.Slice(packet.DataOffset, packet.DataLength);

                        if (_state == ClientState.Connected)
                        {
                            NetcodeLog.Debug("client received connection keep alive packet from server\n");

                            _lastPacketReceiveTime = _time;
                        }
                        else if (_state == ClientState.SendingConnectionResponse)
                        {
                            NetcodeLog.Debug("client received connection keep alive packet from server\n");

                            _lastPacketReceiveTime = _time;
                            _clientIndex = (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(0, 4));
                            _maxClients = (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4, 4));

                            SetState(ClientState.Connected);

                            NetcodeLog.Info("client connected to server\n");
                        }
                    }
                }
                break;

                case PacketType.ConnectionPayload:
                {
                    if (_state == ClientState.Connected && from.Equals(_serverAddress))
                    {
                        NetcodeLog.Debug("client received connection payload packet from server\n");

                        _packetReceiveQueue.Push(buffer.Slice(packet.DataOffset, packet.DataLength), packet.Sequence);

                        _lastPacketReceiveTime = _time;
                    }
                }
                break;

                case PacketType.ConnectionDisconnect:
                {
                    if (_state == ClientState.Connected && from.Equals(_serverAddress))
                    {
                        NetcodeLog.Debug("client received disconnect packet from server\n");

                        _shouldDisconnect = true;
                        _shouldDisconnectState = ClientState.Disconnected;
                        _lastPacketReceiveTime = _time;
                    }
                }
                break;

                default:
                    break;
            }
        }

        /// <summary>
        /// Process a raw packet received for this client from an external socket
        /// architecture. Mirrors netcode_client_process_packet.
        /// </summary>
        public void ProcessPacket(in Address from, Span<byte> packetData)
        {
            ulong currentTimestamp = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            ReadPacketResult packet = PacketIO.ReadPacket(
                packetData,
                hasReadPacketKey: true,
                _readPacketKey,
                _connectToken.ProtocolId,
                currentTimestamp,
                hasPrivateKey: false,
                ReadOnlySpan<byte>.Empty,
                AllowedPackets,
                _replayProtection);

            if (packet.Type < 0)
                return;

            ProcessPacketInternal(in from, in packet, packetData);
        }

        private void ProcessPacketFromSimulator(in Address from, ReadOnlySpan<byte> packetData)
        {
            Span<byte> buffer = _receiveBuffer.AsSpan(0, packetData.Length);
            packetData.CopyTo(buffer);
            ProcessPacket(in from, buffer);
        }

        private void ReceivePackets()
        {
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
                    else if (_serverAddress.Type == AddressType.IPv4)
                    {
                        if (_socketIpv4 != null)
                            packetBytes = _socketIpv4.ReceivePacket(ref from, _receiveBuffer);
                    }
                    else if (_serverAddress.Type == AddressType.IPv6)
                    {
                        if (_socketIpv6 != null)
                            packetBytes = _socketIpv6.ReceivePacket(ref from, _receiveBuffer);
                    }

                    if (packetBytes == 0)
                        break;

                    ProcessPacket(in from, _receiveBuffer.AsSpan(0, packetBytes));
                }
            }
            else
            {
                _config.Simulator.ReceivePackets(in _address, Defines.ClientMaxReceivePackets, _simulatorReceiveHandler);
            }
        }

        // --------------------------------------------------------------
        // packet sending
        // --------------------------------------------------------------

        private void SendPacketToServerInternal(int packetType, ReadOnlySpan<byte> packetData)
        {
            int packetBytes;

            if (packetType == PacketType.ConnectionRequest)
            {
                packetBytes = PacketIO.WriteConnectionRequestPacket(
                    _sendBuffer,
                    _connectToken.VersionInfo,
                    _connectToken.ProtocolId,
                    _connectToken.ExpireTimestamp,
                    _connectToken.Nonce,
                    _connectToken.PrivateData);
                _sequence++;
            }
            else
            {
                packetBytes = PacketIO.WriteEncryptedPacket(
                    _sendBuffer,
                    packetType,
                    packetData,
                    _sequence++,
                    _writePacketKey,
                    _connectToken.ProtocolId);
            }

            SendDispatch.SendPacketToAddress(
                _config.Simulator,
                _config.OverrideSendAndReceive ? _config.SendPacketOverride : null,
                _socketIpv4,
                _socketIpv6,
                in _address,
                in _serverAddress,
                _sendBuffer.AsSpan(0, packetBytes));

            _lastPacketSendTime = _time;
        }

        private void SendPackets()
        {
            switch (_state)
            {
                case ClientState.SendingConnectionRequest:
                {
                    if (_lastPacketSendTime + (1.0 / Defines.PacketSendRate) >= _time)
                        return;

                    NetcodeLog.Debug("client sent connection request packet to server\n");

                    SendPacketToServerInternal(PacketType.ConnectionRequest, ReadOnlySpan<byte>.Empty);
                }
                break;

                case ClientState.SendingConnectionResponse:
                {
                    if (_lastPacketSendTime + (1.0 / Defines.PacketSendRate) >= _time)
                        return;

                    NetcodeLog.Debug("client sent connection response packet to server\n");

                    Span<byte> data = stackalloc byte[8 + Defines.ChallengeTokenBytes];
                    System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(data.Slice(0, 8), _challengeTokenSequence);
                    _challengeTokenData.CopyTo(data.Slice(8));

                    SendPacketToServerInternal(PacketType.ConnectionResponse, data);
                }
                break;

                case ClientState.Connected:
                {
                    if (_lastPacketSendTime + (1.0 / Defines.PacketSendRate) >= _time)
                        return;

                    NetcodeLog.Debug("client sent connection keep alive packet to server\n");

                    Span<byte> data = stackalloc byte[8];
                    data.Clear();

                    SendPacketToServerInternal(PacketType.ConnectionKeepAlive, data);
                }
                break;

                default:
                    break;
            }
        }

        private bool ConnectToNextServer()
        {
            if (_serverAddressIndex + 1 >= _connectToken.NumServerAddresses)
            {
                NetcodeLog.Debug("client has no more servers to connect to\n");
                return false;
            }

            _serverAddressIndex++;
            _serverAddress = _connectToken.ServerAddresses[_serverAddressIndex];

            ResetBeforeNextConnect();

            if (NetcodeLog.Enabled(LogLevel.Info))
                NetcodeLog.Info($"client connecting to next server {_serverAddress} [{_serverAddressIndex + 1}/{_connectToken.NumServerAddresses}]\n");

            SetState(ClientState.SendingConnectionRequest);

            return true;
        }

        /// <summary>Advance the client: receive and process packets, send packets, run timeouts. Call every frame.</summary>
        public void Update(double time)
        {
            _time = time;

            if (_loopback)
                return;

            ReceivePackets();

            SendPackets();

            if (_state > ClientState.Disconnected && _state < ClientState.Connected)
            {
                ulong connectTokenExpireSeconds = _connectToken.ExpireTimestamp - _connectToken.CreateTimestamp;
                if (_time - _connectStartTime >= connectTokenExpireSeconds)
                {
                    NetcodeLog.Info("client connect failed. connect token expired\n");
                    DisconnectInternal(ClientState.ConnectTokenExpired, sendDisconnectPackets: false);
                    return;
                }
            }

            if (_shouldDisconnect)
            {
                if (NetcodeLog.Enabled(LogLevel.Debug))
                    NetcodeLog.Debug($"client should disconnect -> {StateName(_shouldDisconnectState)}\n");
                if (ConnectToNextServer())
                    return;
                DisconnectInternal(_shouldDisconnectState, sendDisconnectPackets: false);
                return;
            }

            switch (_state)
            {
                case ClientState.SendingConnectionRequest:
                {
                    if (_connectToken.TimeoutSeconds > 0 && _lastPacketReceiveTime + _connectToken.TimeoutSeconds < time)
                    {
                        NetcodeLog.Info("client connect failed. connection request timed out\n");
                        if (ConnectToNextServer())
                            return;
                        DisconnectInternal(ClientState.ConnectionRequestTimedOut, sendDisconnectPackets: false);
                        return;
                    }
                }
                break;

                case ClientState.SendingConnectionResponse:
                {
                    if (_connectToken.TimeoutSeconds > 0 && _lastPacketReceiveTime + _connectToken.TimeoutSeconds < time)
                    {
                        NetcodeLog.Info("client connect failed. connection response timed out\n");
                        if (ConnectToNextServer())
                            return;
                        DisconnectInternal(ClientState.ConnectionResponseTimedOut, sendDisconnectPackets: false);
                        return;
                    }
                }
                break;

                case ClientState.Connected:
                {
                    if (_connectToken.TimeoutSeconds > 0 && _lastPacketReceiveTime + _connectToken.TimeoutSeconds < time)
                    {
                        NetcodeLog.Info("client connection timed out\n");
                        DisconnectInternal(ClientState.ConnectionTimedOut, sendDisconnectPackets: false);
                        return;
                    }
                }
                break;

                default:
                    break;
            }
        }

        /// <summary>Send a payload (1..MaxPacketSize bytes) to the server. No-op unless connected.</summary>
        public void SendPacket(ReadOnlySpan<byte> packetData)
        {
            // zero byte payloads are not valid on the wire and would silently vanish at the receiver
            if (packetData.Length <= 0 || packetData.Length > Protocol.MaxPacketSize)
            {
                NetcodeLog.Error($"error: payload packet size is out of range ({packetData.Length})\n");
                return;
            }

            if (_state != ClientState.Connected)
                return;

            if (!_loopback)
            {
                SendPacketToServerInternal(PacketType.ConnectionPayload, packetData);
            }
            else
            {
                _config.SendLoopbackPacket!(_clientIndex, packetData, _sequence++);
            }
        }

        /// <summary>
        /// Pop the oldest received payload into <paramref name="payload"/>
        /// (must be at least MaxPacketSize bytes). Returns the payload length,
        /// or -1 when no packet is queued.
        /// </summary>
        public int ReceivePacket(Span<byte> payload, out ulong sequence)
        {
            return _packetReceiveQueue.Pop(payload, out sequence);
        }

        /// <summary>Disconnect from the server, sending redundant disconnect packets.</summary>
        public void Disconnect()
        {
            DisconnectInternal(ClientState.Disconnected, sendDisconnectPackets: true);
        }

        private void DisconnectInternal(ClientState destinationState, bool sendDisconnectPackets)
        {
            if (_state <= ClientState.Disconnected || _state == destinationState)
                return;

            NetcodeLog.Info("client disconnected\n");

            if (!_loopback && sendDisconnectPackets && _state > ClientState.Disconnected)
            {
                NetcodeLog.Debug("client sent disconnect packets to server\n");

                for (int i = 0; i < Defines.NumDisconnectPackets; i++)
                {
                    if (NetcodeLog.Enabled(LogLevel.Debug))
                        NetcodeLog.Debug($"client sent disconnect packet {i}\n");

                    SendPacketToServerInternal(PacketType.ConnectionDisconnect, ReadOnlySpan<byte>.Empty);
                }
            }

            ResetConnectionData(destinationState);
        }

        // --------------------------------------------------------------
        // loopback
        // --------------------------------------------------------------

        /// <summary>Connect this client in loopback mode: payloads flow through the loopback callbacks, no networking.</summary>
        public void ConnectLoopback(int clientIndex, int maxClients)
        {
            if (_state > ClientState.Disconnected)
                throw new InvalidOperationException("client must be disconnected before connecting loopback");
            NetcodeLog.Info($"client connected to server via loopback as client {clientIndex}\n");
            _state = ClientState.Connected;
            _clientIndex = clientIndex;
            _maxClients = maxClients;
            _loopback = true;
        }

        /// <summary>Disconnect a loopback client.</summary>
        public void DisconnectLoopback()
        {
            if (!_loopback)
                throw new InvalidOperationException("client is not in loopback mode");
            ResetConnectionData(ClientState.Disconnected);
        }

        /// <summary>Deliver a payload to a loopback client (the server side of the loopback pair calls this).</summary>
        public void ProcessLoopbackPacket(ReadOnlySpan<byte> packetData, ulong packetSequence)
        {
            if (!_loopback)
                return;

            if (packetData.Length <= 0 || packetData.Length > Protocol.MaxPacketSize)
                return;

            NetcodeLog.Debug("client processing loopback packet from server\n");
            _packetReceiveQueue.Push(packetData, packetSequence);
        }

        /// <summary>Disconnect (if needed) and release the sockets.</summary>
        public void Dispose()
        {
            if (_disposed)
                return;
            _disposed = true;
            if (!_loopback)
                Disconnect();
            else
                DisconnectLoopback();
            _socketIpv4?.Dispose();
            _socketIpv6?.Dispose();
            _packetReceiveQueue.Clear();
        }
    }
}
