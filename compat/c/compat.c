/*
    compat.c — the C half of the netcode.cs interop gate.

    Builds against the REAL C reference implementation by including netcode.c
    directly (the same technique the C repo's fuzz harnesses use), so it can
    reach the internal write/encrypt functions with fixed keys, nonces and
    timestamps and produce deterministic goldens.

    Subcommands:
        goldens <dir>            write golden files (fixed keys/nonces/timestamps)
        verify <dir>             read + decrypt + validate golden files (either side's)
        mint <file> <address>    mint a connect token with the shared test key
        server <port>            run a server session leg (connect/exchange/disconnect)
        client <port> <token>    run a client session leg against a server

    Exit code is the verdict.
*/

#include "netcode.c"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define GOLDEN_PROTOCOL_ID 0x1122334455667788ULL
#define GOLDEN_CLIENT_ID 0x1122AABBCCDD3344ULL
#define GOLDEN_TIMEOUT_SECONDS 15
#define GOLDEN_EXPIRE_TIMESTAMP 0x1234567890ABCDEFULL
#define GOLDEN_CREATE_TIMESTAMP ( GOLDEN_EXPIRE_TIMESTAMP - 30 )
#define GOLDEN_CHALLENGE_SEQUENCE 0xBADDULL

#define SESSION_PROTOCOL_ID 0x1122334455667788ULL
#define SESSION_NUM_PAYLOADS 10

/* TEST KEY ONLY — the fixed key from the C reference test suite. published in
   two public repositories; obviously non-production. */
static uint8_t session_private_key[NETCODE_KEY_BYTES] = {
    0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea,
    0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
    0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
    0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1 };

static void fill_pattern( uint8_t * data, int bytes, int offset )
{
    int i;
    for ( i = 0; i < bytes; i++ )
        data[i] = (uint8_t) ( i + offset );
}

static int write_file( const char * dir, const char * name, const uint8_t * data, int bytes )
{
    char path[1024];
    snprintf( path, sizeof(path), "%s/%s", dir, name );
    FILE * file = fopen( path, "wb" );
    if ( !file )
    {
        printf( "error: could not open %s for writing\n", path );
        return 0;
    }
    fwrite( data, 1, (size_t) bytes, file );
    fclose( file );
    return 1;
}

static int read_file( const char * dir, const char * name, uint8_t * data, int expected_bytes )
{
    char path[1024];
    snprintf( path, sizeof(path), "%s/%s", dir, name );
    FILE * file = fopen( path, "rb" );
    if ( !file )
    {
        printf( "error: could not open %s for reading\n", path );
        return 0;
    }
    int bytes = (int) fread( data, 1, (size_t) expected_bytes + 1, file );
    fclose( file );
    if ( bytes != expected_bytes )
    {
        printf( "error: %s is %d bytes, expected %d\n", path, bytes, expected_bytes );
        return 0;
    }
    return 1;
}

/* golden object construction (shared between goldens + verify) */

static void golden_addresses( struct netcode_address_t * addresses )
{
    netcode_parse_address( "127.0.0.1:40000", &addresses[0] );
    netcode_parse_address( "[fe80::202:b3ff:fe1e:8329]:50000", &addresses[1] );
}

static void golden_private_token_struct( struct netcode_connect_token_private_t * token )
{
    memset( token, 0, sizeof( *token ) );
    token->client_id = GOLDEN_CLIENT_ID;
    token->timeout_seconds = GOLDEN_TIMEOUT_SECONDS;
    token->num_server_addresses = 2;
    golden_addresses( token->server_addresses );
    fill_pattern( token->client_to_server_key, NETCODE_KEY_BYTES, 2 );
    fill_pattern( token->server_to_client_key, NETCODE_KEY_BYTES, 3 );
    fill_pattern( token->user_data, NETCODE_USER_DATA_BYTES, 0 );
}

static void golden_keys_and_nonce( uint8_t * token_key, uint8_t * challenge_key, uint8_t * packet_key, uint8_t * nonce )
{
    fill_pattern( token_key, NETCODE_KEY_BYTES, 1 );
    fill_pattern( challenge_key, NETCODE_KEY_BYTES, 4 );
    fill_pattern( packet_key, NETCODE_KEY_BYTES, 5 );
    fill_pattern( nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES, 6 );
}

static int build_golden_private_token( uint8_t * buffer /* 1024 */ )
{
    struct netcode_connect_token_private_t token;
    golden_private_token_struct( &token );
    netcode_write_connect_token_private( &token, buffer, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

    uint8_t token_key[NETCODE_KEY_BYTES], challenge_key[NETCODE_KEY_BYTES], packet_key[NETCODE_KEY_BYTES];
    uint8_t nonce[NETCODE_CONNECT_TOKEN_NONCE_BYTES];
    golden_keys_and_nonce( token_key, challenge_key, packet_key, nonce );

    return netcode_encrypt_connect_token_private( buffer, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, NETCODE_VERSION_INFO,
                                                  GOLDEN_PROTOCOL_ID, GOLDEN_EXPIRE_TIMESTAMP, nonce, token_key ) == NETCODE_OK;
}

static int build_golden_challenge_token( uint8_t * buffer /* 300 */ )
{
    struct netcode_challenge_token_t token;
    memset( &token, 0, sizeof( token ) );
    token.client_id = GOLDEN_CLIENT_ID;
    fill_pattern( token.user_data, NETCODE_USER_DATA_BYTES, 0 );
    netcode_write_challenge_token( &token, buffer, NETCODE_CHALLENGE_TOKEN_BYTES );

    uint8_t token_key[NETCODE_KEY_BYTES], challenge_key[NETCODE_KEY_BYTES], packet_key[NETCODE_KEY_BYTES];
    uint8_t nonce[NETCODE_CONNECT_TOKEN_NONCE_BYTES];
    golden_keys_and_nonce( token_key, challenge_key, packet_key, nonce );

    /* Legacy golden uses the historical empty-AD construction. The live
       mapping-bound scenario below exercises the C reference's new API. */
    uint8_t challenge_nonce[12] = { 0 };
    uint8_t * p = challenge_nonce + 4;
    netcode_write_uint64( &p, GOLDEN_CHALLENGE_SEQUENCE );
    return netcode_encrypt_aead( buffer, NETCODE_CHALLENGE_TOKEN_BYTES - NETCODE_MAC_BYTES,
                                 NULL, 0, challenge_nonce, challenge_key ) == NETCODE_OK;
}

static int do_goldens( const char * dir )
{
    uint8_t token_key[NETCODE_KEY_BYTES], challenge_key[NETCODE_KEY_BYTES], packet_key[NETCODE_KEY_BYTES];
    uint8_t nonce[NETCODE_CONNECT_TOKEN_NONCE_BYTES];
    golden_keys_and_nonce( token_key, challenge_key, packet_key, nonce );

    /* 1. encrypted private connect token */

    uint8_t private_token[NETCODE_CONNECT_TOKEN_PRIVATE_BYTES];
    if ( !build_golden_private_token( private_token ) )
        return 0;
    if ( !write_file( dir, "private_token.bin", private_token, sizeof( private_token ) ) )
        return 0;

    /* 2. public connect token wrapping it */

    struct netcode_connect_token_t connect_token;
    memset( &connect_token, 0, sizeof( connect_token ) );
    memcpy( connect_token.version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
    connect_token.protocol_id = GOLDEN_PROTOCOL_ID;
    connect_token.create_timestamp = GOLDEN_CREATE_TIMESTAMP;
    connect_token.expire_timestamp = GOLDEN_EXPIRE_TIMESTAMP;
    memcpy( connect_token.nonce, nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES );
    memcpy( connect_token.private_data, private_token, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
    connect_token.num_server_addresses = 2;
    golden_addresses( connect_token.server_addresses );
    fill_pattern( connect_token.client_to_server_key, NETCODE_KEY_BYTES, 2 );
    fill_pattern( connect_token.server_to_client_key, NETCODE_KEY_BYTES, 3 );
    connect_token.timeout_seconds = GOLDEN_TIMEOUT_SECONDS;

    uint8_t public_token[NETCODE_CONNECT_TOKEN_BYTES];
    netcode_write_connect_token( &connect_token, public_token, NETCODE_CONNECT_TOKEN_BYTES );
    if ( !write_file( dir, "public_token.bin", public_token, sizeof( public_token ) ) )
        return 0;

    /* 3. encrypted challenge token */

    uint8_t challenge_token[NETCODE_CHALLENGE_TOKEN_BYTES];
    if ( !build_golden_challenge_token( challenge_token ) )
        return 0;
    if ( !write_file( dir, "challenge_token.bin", challenge_token, sizeof( challenge_token ) ) )
        return 0;

    /* 4. every packet type, fixed keys and sequences */

    uint8_t buffer[NETCODE_MAX_PACKET_BYTES * 2];
    int bytes;

    {
        struct netcode_connection_request_packet_t packet;
        packet.packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
        memcpy( packet.version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
        packet.protocol_id = GOLDEN_PROTOCOL_ID;
        packet.connect_token_expire_timestamp = GOLDEN_EXPIRE_TIMESTAMP;
        memcpy( packet.connect_token_nonce, nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES );
        memcpy( packet.connect_token_data, private_token, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
        bytes = netcode_write_packet( &packet, buffer, sizeof( buffer ), 0, packet_key, GOLDEN_PROTOCOL_ID );
        if ( bytes <= 0 || !write_file( dir, "packet_request.bin", buffer, bytes ) )
            return 0;
    }

    {
        struct netcode_connection_denied_packet_t packet;
        packet.packet_type = NETCODE_CONNECTION_DENIED_PACKET;
        bytes = netcode_write_packet( &packet, buffer, sizeof( buffer ), 1ULL << 63, packet_key, GOLDEN_PROTOCOL_ID );
        if ( bytes <= 0 || !write_file( dir, "packet_denied.bin", buffer, bytes ) )
            return 0;
    }

    {
        struct netcode_connection_challenge_packet_t packet;
        packet.packet_type = NETCODE_CONNECTION_CHALLENGE_PACKET;
        packet.challenge_token_sequence = GOLDEN_CHALLENGE_SEQUENCE;
        memcpy( packet.challenge_token_data, challenge_token, NETCODE_CHALLENGE_TOKEN_BYTES );
        bytes = netcode_write_packet( &packet, buffer, sizeof( buffer ), ( 1ULL << 63 ) + 5, packet_key, GOLDEN_PROTOCOL_ID );
        if ( bytes <= 0 || !write_file( dir, "packet_challenge.bin", buffer, bytes ) )
            return 0;
    }

    {
        struct netcode_connection_response_packet_t packet;
        packet.packet_type = NETCODE_CONNECTION_RESPONSE_PACKET;
        packet.challenge_token_sequence = GOLDEN_CHALLENGE_SEQUENCE;
        memcpy( packet.challenge_token_data, challenge_token, NETCODE_CHALLENGE_TOKEN_BYTES );
        bytes = netcode_write_packet( &packet, buffer, sizeof( buffer ), 0x1F, packet_key, GOLDEN_PROTOCOL_ID );
        if ( bytes <= 0 || !write_file( dir, "packet_response.bin", buffer, bytes ) )
            return 0;
    }

    {
        struct netcode_connection_keep_alive_packet_t packet;
        packet.packet_type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
        packet.client_index = 5;
        packet.max_clients = 32;
        bytes = netcode_write_packet( &packet, buffer, sizeof( buffer ), 0x11223344, packet_key, GOLDEN_PROTOCOL_ID );
        if ( bytes <= 0 || !write_file( dir, "packet_keepalive.bin", buffer, bytes ) )
            return 0;
    }

    {
        uint8_t payload_buffer[sizeof( struct netcode_connection_payload_packet_t ) + NETCODE_MAX_PAYLOAD_BYTES];
        struct netcode_connection_payload_packet_t * packet = (struct netcode_connection_payload_packet_t*) payload_buffer;
        packet->packet_type = NETCODE_CONNECTION_PAYLOAD_PACKET;
        packet->payload_bytes = NETCODE_MAX_PAYLOAD_BYTES;
        fill_pattern( packet->payload_data, NETCODE_MAX_PAYLOAD_BYTES, 0 );
        bytes = netcode_write_packet( packet, buffer, sizeof( buffer ), 1000, packet_key, GOLDEN_PROTOCOL_ID );
        if ( bytes <= 0 || !write_file( dir, "packet_payload.bin", buffer, bytes ) )
            return 0;
    }

    {
        struct netcode_connection_disconnect_packet_t packet;
        packet.packet_type = NETCODE_CONNECTION_DISCONNECT_PACKET;
        bytes = netcode_write_packet( &packet, buffer, sizeof( buffer ), 7, packet_key, GOLDEN_PROTOCOL_ID );
        if ( bytes <= 0 || !write_file( dir, "packet_disconnect.bin", buffer, bytes ) )
            return 0;
    }

    printf( "goldens written to %s\n", dir );
    return 1;
}

#define VERIFY( condition )                                                     \
    do {                                                                        \
        if ( !(condition) )                                                     \
        {                                                                       \
            printf( "verify failed: %s, line %d\n", #condition, __LINE__ );     \
            return 0;                                                           \
        }                                                                       \
    } while (0)

static int do_verify( const char * dir )
{
    uint8_t token_key[NETCODE_KEY_BYTES], challenge_key[NETCODE_KEY_BYTES], packet_key[NETCODE_KEY_BYTES];
    uint8_t nonce[NETCODE_CONNECT_TOKEN_NONCE_BYTES];
    golden_keys_and_nonce( token_key, challenge_key, packet_key, nonce );

    struct netcode_address_t expected_addresses[2];
    golden_addresses( expected_addresses );

    uint8_t expected_user_data[NETCODE_USER_DATA_BYTES];
    fill_pattern( expected_user_data, NETCODE_USER_DATA_BYTES, 0 );

    uint8_t expected_c2s[NETCODE_KEY_BYTES], expected_s2c[NETCODE_KEY_BYTES];
    fill_pattern( expected_c2s, NETCODE_KEY_BYTES, 2 );
    fill_pattern( expected_s2c, NETCODE_KEY_BYTES, 3 );

    /* 1. private connect token decrypts and reads back the golden fields */

    uint8_t private_token[NETCODE_CONNECT_TOKEN_PRIVATE_BYTES];
    if ( !read_file( dir, "private_token.bin", private_token, sizeof( private_token ) ) )
        return 0;

    VERIFY( netcode_decrypt_connect_token_private( private_token, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, NETCODE_VERSION_INFO,
                                                   GOLDEN_PROTOCOL_ID, GOLDEN_EXPIRE_TIMESTAMP, nonce, token_key ) == NETCODE_OK );

    struct netcode_connect_token_private_t private_struct;
    VERIFY( netcode_read_connect_token_private( private_token, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, &private_struct ) == NETCODE_OK );
    VERIFY( private_struct.client_id == GOLDEN_CLIENT_ID );
    VERIFY( private_struct.timeout_seconds == GOLDEN_TIMEOUT_SECONDS );
    VERIFY( private_struct.num_server_addresses == 2 );
    VERIFY( netcode_address_equal( &private_struct.server_addresses[0], &expected_addresses[0] ) );
    VERIFY( netcode_address_equal( &private_struct.server_addresses[1], &expected_addresses[1] ) );
    VERIFY( memcmp( private_struct.client_to_server_key, expected_c2s, NETCODE_KEY_BYTES ) == 0 );
    VERIFY( memcmp( private_struct.server_to_client_key, expected_s2c, NETCODE_KEY_BYTES ) == 0 );
    VERIFY( memcmp( private_struct.user_data, expected_user_data, NETCODE_USER_DATA_BYTES ) == 0 );

    /* 2. public connect token reads back */

    uint8_t public_token[NETCODE_CONNECT_TOKEN_BYTES];
    if ( !read_file( dir, "public_token.bin", public_token, sizeof( public_token ) ) )
        return 0;

    struct netcode_connect_token_t connect_token;
    VERIFY( netcode_read_connect_token( public_token, NETCODE_CONNECT_TOKEN_BYTES, &connect_token ) == NETCODE_OK );
    VERIFY( connect_token.protocol_id == GOLDEN_PROTOCOL_ID );
    VERIFY( connect_token.create_timestamp == GOLDEN_CREATE_TIMESTAMP );
    VERIFY( connect_token.expire_timestamp == GOLDEN_EXPIRE_TIMESTAMP );
    VERIFY( connect_token.timeout_seconds == GOLDEN_TIMEOUT_SECONDS );
    VERIFY( connect_token.num_server_addresses == 2 );
    VERIFY( netcode_address_equal( &connect_token.server_addresses[0], &expected_addresses[0] ) );
    VERIFY( netcode_address_equal( &connect_token.server_addresses[1], &expected_addresses[1] ) );

    /* 3. challenge token decrypts and reads back */

    uint8_t challenge_token[NETCODE_CHALLENGE_TOKEN_BYTES];
    if ( !read_file( dir, "challenge_token.bin", challenge_token, sizeof( challenge_token ) ) )
        return 0;

    uint8_t challenge_nonce[12] = { 0 };
    uint8_t * p = challenge_nonce + 4;
    netcode_write_uint64( &p, GOLDEN_CHALLENGE_SEQUENCE );
    VERIFY( netcode_decrypt_aead( challenge_token, NETCODE_CHALLENGE_TOKEN_BYTES,
                                 NULL, 0, challenge_nonce, challenge_key ) == NETCODE_OK );

    struct netcode_challenge_token_t challenge_struct;
    VERIFY( netcode_read_challenge_token( challenge_token, NETCODE_CHALLENGE_TOKEN_BYTES, &challenge_struct ) == NETCODE_OK );
    VERIFY( challenge_struct.client_id == GOLDEN_CLIENT_ID );
    VERIFY( memcmp( challenge_struct.user_data, expected_user_data, NETCODE_USER_DATA_BYTES ) == 0 );

    /* 4. every packet type reads (and decrypts) back */

    uint8_t allowed_packets[NETCODE_CONNECTION_NUM_PACKETS];
    memset( allowed_packets, 1, sizeof( allowed_packets ) );

    uint8_t buffer[NETCODE_MAX_PACKET_BYTES * 2];
    uint64_t sequence;

    {
        int bytes = 1 + NETCODE_VERSION_INFO_BYTES + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES;
        if ( !read_file( dir, "packet_request.bin", buffer, bytes ) )
            return 0;
        struct netcode_connection_request_packet_t * packet = (struct netcode_connection_request_packet_t*)
            netcode_read_packet( buffer, bytes, &sequence, packet_key, GOLDEN_PROTOCOL_ID, 0, 0, UINT64_MAX, token_key, allowed_packets, NULL, NULL, NULL );
        VERIFY( packet != NULL );
        VERIFY( packet->packet_type == NETCODE_CONNECTION_REQUEST_PACKET );
        VERIFY( packet->protocol_id == GOLDEN_PROTOCOL_ID );
        VERIFY( packet->connect_token_expire_timestamp == GOLDEN_EXPIRE_TIMESTAMP );
        free( packet );
    }

    {
        int bytes = 1 + 8 + NETCODE_MAC_BYTES;      /* prefix + 8 sequence bytes + mac */
        if ( !read_file( dir, "packet_denied.bin", buffer, bytes ) )
            return 0;
        void * packet = netcode_read_packet( buffer, bytes, &sequence, packet_key, GOLDEN_PROTOCOL_ID, 0, 0, UINT64_MAX, NULL, allowed_packets, NULL, NULL, NULL );
        VERIFY( packet != NULL );
        VERIFY( ( (uint8_t*) packet )[0] == NETCODE_CONNECTION_DENIED_PACKET );
        VERIFY( sequence == 1ULL << 63 );
        free( packet );
    }

    {
        int bytes = 1 + 8 + 8 + NETCODE_CHALLENGE_TOKEN_BYTES + NETCODE_MAC_BYTES;
        if ( !read_file( dir, "packet_challenge.bin", buffer, bytes ) )
            return 0;
        struct netcode_connection_challenge_packet_t * packet = (struct netcode_connection_challenge_packet_t*)
            netcode_read_packet( buffer, bytes, &sequence, packet_key, GOLDEN_PROTOCOL_ID, 0, 0, UINT64_MAX, NULL, allowed_packets, NULL, NULL, NULL );
        VERIFY( packet != NULL );
        VERIFY( packet->packet_type == NETCODE_CONNECTION_CHALLENGE_PACKET );
        VERIFY( packet->challenge_token_sequence == GOLDEN_CHALLENGE_SEQUENCE );
        VERIFY( sequence == ( 1ULL << 63 ) + 5 );
        free( packet );
    }

    {
        int bytes = 1 + 1 + 8 + NETCODE_CHALLENGE_TOKEN_BYTES + NETCODE_MAC_BYTES;
        if ( !read_file( dir, "packet_response.bin", buffer, bytes ) )
            return 0;
        struct netcode_connection_response_packet_t * packet = (struct netcode_connection_response_packet_t*)
            netcode_read_packet( buffer, bytes, &sequence, packet_key, GOLDEN_PROTOCOL_ID, 0, 0, UINT64_MAX, NULL, allowed_packets, NULL, NULL, NULL );
        VERIFY( packet != NULL );
        VERIFY( packet->packet_type == NETCODE_CONNECTION_RESPONSE_PACKET );
        VERIFY( packet->challenge_token_sequence == GOLDEN_CHALLENGE_SEQUENCE );
        VERIFY( sequence == 0x1F );
        free( packet );
    }

    {
        int bytes = 1 + 4 + 8 + NETCODE_MAC_BYTES;
        if ( !read_file( dir, "packet_keepalive.bin", buffer, bytes ) )
            return 0;
        struct netcode_connection_keep_alive_packet_t * packet = (struct netcode_connection_keep_alive_packet_t*)
            netcode_read_packet( buffer, bytes, &sequence, packet_key, GOLDEN_PROTOCOL_ID, 0, 0, UINT64_MAX, NULL, allowed_packets, NULL, NULL, NULL );
        VERIFY( packet != NULL );
        VERIFY( packet->packet_type == NETCODE_CONNECTION_KEEP_ALIVE_PACKET );
        VERIFY( packet->client_index == 5 );
        VERIFY( packet->max_clients == 32 );
        VERIFY( sequence == 0x11223344 );
        free( packet );
    }

    {
        int bytes = 1 + 2 + NETCODE_MAX_PAYLOAD_BYTES + NETCODE_MAC_BYTES;
        if ( !read_file( dir, "packet_payload.bin", buffer, bytes ) )
            return 0;
        struct netcode_connection_payload_packet_t * packet = (struct netcode_connection_payload_packet_t*)
            netcode_read_packet( buffer, bytes, &sequence, packet_key, GOLDEN_PROTOCOL_ID, 0, 0, UINT64_MAX, NULL, allowed_packets, NULL, NULL, NULL );
        VERIFY( packet != NULL );
        VERIFY( packet->packet_type == NETCODE_CONNECTION_PAYLOAD_PACKET );
        VERIFY( packet->payload_bytes == NETCODE_MAX_PAYLOAD_BYTES );
        uint8_t expected_payload[NETCODE_MAX_PAYLOAD_BYTES];
        fill_pattern( expected_payload, NETCODE_MAX_PAYLOAD_BYTES, 0 );
        VERIFY( memcmp( packet->payload_data, expected_payload, NETCODE_MAX_PAYLOAD_BYTES ) == 0 );
        VERIFY( sequence == 1000 );
        free( packet );
    }

    {
        int bytes = 1 + 1 + NETCODE_MAC_BYTES;
        if ( !read_file( dir, "packet_disconnect.bin", buffer, bytes ) )
            return 0;
        void * packet = netcode_read_packet( buffer, bytes, &sequence, packet_key, GOLDEN_PROTOCOL_ID, 0, 0, UINT64_MAX, NULL, allowed_packets, NULL, NULL, NULL );
        VERIFY( packet != NULL );
        VERIFY( ( (uint8_t*) packet )[0] == NETCODE_CONNECTION_DISCONNECT_PACKET );
        VERIFY( sequence == 7 );
        free( packet );
    }

    printf( "verify passed: %s\n", dir );
    return 1;
}

static int do_mint( const char * filename, const char * server_address )
{
    uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];
    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    fill_pattern( user_data, NETCODE_USER_DATA_BYTES, 0 );

    uint64_t client_id = 0;
    netcode_random_bytes( (uint8_t*) &client_id, 8 );

    if ( netcode_generate_connect_token( 1, &server_address, &server_address, 30, 15, client_id,
                                         SESSION_PROTOCOL_ID, session_private_key, user_data, connect_token ) != NETCODE_OK )
    {
        printf( "error: failed to mint connect token\n" );
        return 0;
    }

    FILE * file = fopen( filename, "wb" );
    if ( !file )
        return 0;
    fwrite( connect_token, 1, NETCODE_CONNECT_TOKEN_BYTES, file );
    fclose( file );
    printf( "minted connect token (C) -> %s\n", filename );
    return 1;
}

static int do_server( int port )
{
    char bind_address[64];
    snprintf( bind_address, sizeof(bind_address), "127.0.0.1:%d", port );

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.protocol_id = SESSION_PROTOCOL_ID;
    memcpy( server_config.private_key, session_private_key, NETCODE_KEY_BYTES );

    struct netcode_server_t * server = netcode_server_create( bind_address, &server_config, 0.0 );
    if ( !server )
    {
        printf( "error: failed to create server\n" );
        return 0;
    }

    netcode_server_start( server, 1 );

    uint8_t payload[NETCODE_MAX_PACKET_SIZE];
    fill_pattern( payload, NETCODE_MAX_PACKET_SIZE, 0 );

    int payloads_received = 0;
    int client_was_connected = 0;
    double time = 0.0;
    double delta_time = 0.01;
    int iterations = 6000;      /* 60 seconds of real time at 10ms per iteration */
    int result = 0;

    printf( "C server listening on %s\n", bind_address );

    int i;
    for ( i = 0; i < iterations; i++ )
    {
        netcode_server_update( server, time );

        if ( netcode_server_client_connected( server, 0 ) )
        {
            client_was_connected = 1;

            netcode_server_send_packet( server, 0, payload, NETCODE_MAX_PACKET_SIZE );

            while ( 1 )
            {
                int packet_bytes;
                uint64_t packet_sequence;
                uint8_t * packet = netcode_server_receive_packet( server, 0, &packet_bytes, &packet_sequence );
                if ( !packet )
                    break;
                if ( packet_bytes != NETCODE_MAX_PACKET_SIZE || memcmp( packet, payload, NETCODE_MAX_PACKET_SIZE ) != 0 )
                {
                    printf( "error: C server received bad payload\n" );
                    netcode_server_free_packet( server, packet );
                    netcode_server_destroy( server );
                    return 0;
                }
                payloads_received++;
                netcode_server_free_packet( server, packet );
            }
        }
        else if ( client_was_connected )
        {
            /* the client disconnected. success requires that we saw its payloads and
               that the disconnect was client initiated, not a timeout. */
            int reason = netcode_server_client_disconnect_reason( server, 0 );
            if ( payloads_received >= SESSION_NUM_PAYLOADS && reason == NETCODE_SERVER_CLIENT_DISCONNECT_REASON_CLIENT_DISCONNECT )
            {
                printf( "C server: client connected, %d payloads received, clean client disconnect\n", payloads_received );
                result = 1;
            }
            else
            {
                printf( "error: C server: payloads_received=%d disconnect_reason=%d\n", payloads_received, reason );
            }
            break;
        }

        netcode_sleep( delta_time );
        time += delta_time;
    }

    if ( !client_was_connected )
        printf( "error: C server: no client connected within the time limit\n" );

    netcode_server_destroy( server );
    return result;
}

static int do_client( int port, const char * token_file )
{
    (void) port;

    uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];
    {
        FILE * file = fopen( token_file, "rb" );
        if ( !file )
        {
            printf( "error: could not open token file %s\n", token_file );
            return 0;
        }
        int bytes = (int) fread( connect_token, 1, NETCODE_CONNECT_TOKEN_BYTES, file );
        fclose( file );
        if ( bytes != NETCODE_CONNECT_TOKEN_BYTES )
        {
            printf( "error: token file is %d bytes\n", bytes );
            return 0;
        }
    }

    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );

    struct netcode_client_t * client = netcode_client_create( "0.0.0.0:0", &client_config, 0.0 );
    if ( !client )
    {
        printf( "error: failed to create client\n" );
        return 0;
    }

    netcode_client_connect( client, connect_token );

    uint8_t payload[NETCODE_MAX_PACKET_SIZE];
    fill_pattern( payload, NETCODE_MAX_PACKET_SIZE, 0 );

    int payloads_received = 0;
    int payloads_sent = 0;
    double time = 0.0;
    double delta_time = 0.01;
    int iterations = 6000;
    int result = 0;

    int i;
    for ( i = 0; i < iterations; i++ )
    {
        netcode_client_update( client, time );

        if ( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED )
        {
            netcode_client_send_packet( client, payload, NETCODE_MAX_PACKET_SIZE );
            payloads_sent++;

            while ( 1 )
            {
                int packet_bytes;
                uint64_t packet_sequence;
                uint8_t * packet = netcode_client_receive_packet( client, &packet_bytes, &packet_sequence );
                if ( !packet )
                    break;
                if ( packet_bytes != NETCODE_MAX_PACKET_SIZE || memcmp( packet, payload, NETCODE_MAX_PACKET_SIZE ) != 0 )
                {
                    printf( "error: C client received bad payload\n" );
                    netcode_client_free_packet( client, packet );
                    netcode_client_destroy( client );
                    return 0;
                }
                payloads_received++;
                netcode_client_free_packet( client, packet );
            }

            /* keep sending past the receive threshold so the other side reliably
               sees its quota before the disconnect lands */
            if ( payloads_received >= SESSION_NUM_PAYLOADS && payloads_sent >= SESSION_NUM_PAYLOADS * 2 )
            {
                printf( "C client: connected as client %d, %d payloads received, disconnecting\n",
                        netcode_client_index( client ), payloads_received );
                netcode_client_disconnect( client );
                result = 1;
                break;
            }
        }
        else if ( netcode_client_state( client ) < NETCODE_CLIENT_STATE_DISCONNECTED )
        {
            printf( "error: C client entered error state %d\n", netcode_client_state( client ) );
            break;
        }

        netcode_sleep( delta_time );
        time += delta_time;
    }

    if ( !result && payloads_received < SESSION_NUM_PAYLOADS )
        printf( "error: C client: only %d payloads received\n", payloads_received );

    netcode_client_destroy( client );
    return result;
}

static int do_diff_packets( void )
{
    uint8_t token_key[NETCODE_KEY_BYTES], challenge_key[NETCODE_KEY_BYTES], packet_key[NETCODE_KEY_BYTES];
    uint8_t nonce[NETCODE_CONNECT_TOKEN_NONCE_BYTES];
    uint8_t private_token[NETCODE_CONNECT_TOKEN_PRIVATE_BYTES];
    uint8_t buffer[NETCODE_MAX_PACKET_BYTES * 2];
    uint8_t allowed_packets[NETCODE_CONNECTION_NUM_PACKETS];
    struct netcode_replay_protection_t replay;
    uint64_t current_timestamp = GOLDEN_EXPIRE_TIMESTAMP - 1;
    uint64_t sequence;
    int bytes;

    (void) challenge_key;

    golden_keys_and_nonce( token_key, challenge_key, packet_key, nonce );
    memset( allowed_packets, 1, sizeof( allowed_packets ) );
    memset( &replay, 0, sizeof( replay ) );

    if ( !build_golden_private_token( private_token ) )
        return 0;

    /* 0: valid connection request packet */
    {
        struct netcode_connection_request_packet_t packet;
        packet.packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
        memcpy( packet.version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
        packet.protocol_id = GOLDEN_PROTOCOL_ID;
        packet.connect_token_expire_timestamp = GOLDEN_EXPIRE_TIMESTAMP;
        memcpy( packet.connect_token_nonce, nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES );
        memcpy( packet.connect_token_data, private_token, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
        bytes = netcode_write_packet( &packet, buffer, sizeof( buffer ), 0, packet_key, GOLDEN_PROTOCOL_ID );

        void * result = netcode_read_packet( buffer, bytes, &sequence, packet_key, GOLDEN_PROTOCOL_ID, current_timestamp, 0, UINT64_MAX, token_key, allowed_packets, NULL, NULL, NULL );
        if ( result )
            printf( "0 request 0 %d\n", NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
        else
            printf( "0 refused 0 0\n" );
    }

    /* 1: bad prefix byte (type 0, 7 sequence bytes) */
    {
        uint8_t payload_storage[sizeof( struct netcode_connection_payload_packet_t ) + 100];
        struct netcode_connection_payload_packet_t * p = (struct netcode_connection_payload_packet_t*) payload_storage;
        uint8_t payload[100];
        int i;
        for ( i = 0; i < (int) sizeof( payload ); i++ )
            payload[i] = (uint8_t) i;

        p->packet_type = NETCODE_CONNECTION_PAYLOAD_PACKET;
        p->payload_bytes = sizeof( payload );
        memcpy( p->payload_data, payload, sizeof( payload ) );
        bytes = netcode_write_packet( p, buffer, sizeof( buffer ), 1000, packet_key, GOLDEN_PROTOCOL_ID );
        buffer[0] = 0x70;

        void * result = netcode_read_packet( buffer, bytes, &sequence, packet_key, GOLDEN_PROTOCOL_ID, current_timestamp, 0, UINT64_MAX, NULL, allowed_packets, NULL, NULL, NULL );
        printf( "1 %s %lu 0\n", result ? "payload" : "refused", result ? (unsigned long) sequence : 0UL );
        if ( result )
            free( result );
    }

    /* 2: truncated connection request packet */
    {
        struct netcode_connection_request_packet_t packet;
        packet.packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
        memcpy( packet.version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
        packet.protocol_id = GOLDEN_PROTOCOL_ID;
        packet.connect_token_expire_timestamp = GOLDEN_EXPIRE_TIMESTAMP;
        memcpy( packet.connect_token_nonce, nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES );
        memcpy( packet.connect_token_data, private_token, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
        bytes = netcode_write_packet( &packet, buffer, sizeof( buffer ), 0, packet_key, GOLDEN_PROTOCOL_ID );

        void * result = netcode_read_packet( buffer, bytes - 1, &sequence, packet_key, GOLDEN_PROTOCOL_ID, current_timestamp, 0, UINT64_MAX, token_key, allowed_packets, NULL, NULL, NULL );
        printf( "2 %s %lu 0\n", result ? "request" : "refused", result ? (unsigned long) sequence : 0UL );
        if ( result )
            free( result );
    }

    /* 3: wrong connection request packet size */
    {
        struct netcode_connection_request_packet_t packet;
        packet.packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
        memcpy( packet.version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
        packet.protocol_id = GOLDEN_PROTOCOL_ID;
        packet.connect_token_expire_timestamp = GOLDEN_EXPIRE_TIMESTAMP;
        memcpy( packet.connect_token_nonce, nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES );
        memcpy( packet.connect_token_data, private_token, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
        bytes = netcode_write_packet( &packet, buffer, sizeof( buffer ), 0, packet_key, GOLDEN_PROTOCOL_ID );

        void * result = netcode_read_packet( buffer, bytes - 2, &sequence, packet_key, GOLDEN_PROTOCOL_ID, current_timestamp, 0, UINT64_MAX, token_key, allowed_packets, NULL, NULL, NULL );
        printf( "3 %s %lu 0\n", result ? "request" : "refused", result ? (unsigned long) sequence : 0UL );
        if ( result )
            free( result );
    }

    /* 4: valid encrypted payload packet */
    {
        uint8_t payload_storage[sizeof( struct netcode_connection_payload_packet_t ) + 100];
        struct netcode_connection_payload_packet_t * p = (struct netcode_connection_payload_packet_t*) payload_storage;
        uint8_t payload[100];
        int i;
        for ( i = 0; i < (int) sizeof( payload ); i++ )
            payload[i] = (uint8_t) i;

        p->packet_type = NETCODE_CONNECTION_PAYLOAD_PACKET;
        p->payload_bytes = sizeof( payload );
        memcpy( p->payload_data, payload, sizeof( payload ) );
        bytes = netcode_write_packet( p, buffer, sizeof( buffer ), 1000, packet_key, GOLDEN_PROTOCOL_ID );

        void * result = netcode_read_packet( buffer, bytes, &sequence, packet_key, GOLDEN_PROTOCOL_ID, current_timestamp, 0, UINT64_MAX, NULL, allowed_packets, &replay, NULL, NULL );
        if ( result )
            printf( "4 payload %lu %d\n", (unsigned long) sequence, ( (struct netcode_connection_payload_packet_t*) result )->payload_bytes );
        else
            printf( "4 refused 0 0\n" );
        if ( result )
            free( result );
    }

    /* 5: replayed payload packet */
    {
        uint8_t payload_storage[sizeof( struct netcode_connection_payload_packet_t ) + 100];
        struct netcode_connection_payload_packet_t * p = (struct netcode_connection_payload_packet_t*) payload_storage;
        uint8_t payload[100];
        int i;
        for ( i = 0; i < (int) sizeof( payload ); i++ )
            payload[i] = (uint8_t) i;

        p->packet_type = NETCODE_CONNECTION_PAYLOAD_PACKET;
        p->payload_bytes = sizeof( payload );
        memcpy( p->payload_data, payload, sizeof( payload ) );
        bytes = netcode_write_packet( p, buffer, sizeof( buffer ), 1000, packet_key, GOLDEN_PROTOCOL_ID );

        void * result = netcode_read_packet( buffer, bytes, &sequence, packet_key, GOLDEN_PROTOCOL_ID, current_timestamp, 0, UINT64_MAX, NULL, allowed_packets, &replay, NULL, NULL );
        printf( "5 %s %lu 0\n", result ? "payload" : "refused", result ? (unsigned long) sequence : 0UL );
        if ( result )
            free( result );
    }

    /* 6: wrong version info in connection request */
    {
        struct netcode_connection_request_packet_t packet;
        packet.packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
        memcpy( packet.version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
        packet.protocol_id = GOLDEN_PROTOCOL_ID;
        packet.connect_token_expire_timestamp = GOLDEN_EXPIRE_TIMESTAMP;
        memcpy( packet.connect_token_nonce, nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES );
        memcpy( packet.connect_token_data, private_token, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
        bytes = netcode_write_packet( &packet, buffer, sizeof( buffer ), 0, packet_key, GOLDEN_PROTOCOL_ID );
        buffer[1] = 'X';

        void * result = netcode_read_packet( buffer, bytes, &sequence, packet_key, GOLDEN_PROTOCOL_ID, current_timestamp, 0, UINT64_MAX, token_key, allowed_packets, NULL, NULL, NULL );
        printf( "6 %s %lu 0\n", result ? "request" : "refused", (unsigned long) sequence );
        if ( result )
            free( result );
    }

    /* 7: wrong protocol id in connection request */
    {
        struct netcode_connection_request_packet_t packet;
        packet.packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
        memcpy( packet.version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
        packet.protocol_id = GOLDEN_PROTOCOL_ID;
        packet.connect_token_expire_timestamp = GOLDEN_EXPIRE_TIMESTAMP;
        memcpy( packet.connect_token_nonce, nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES );
        memcpy( packet.connect_token_data, private_token, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
        bytes = netcode_write_packet( &packet, buffer, sizeof( buffer ), 0, packet_key, GOLDEN_PROTOCOL_ID );
        {
            uint64_t wrong = ~GOLDEN_PROTOCOL_ID;
            int i;
            for ( i = 0; i < 8; i++ )
                buffer[1 + NETCODE_VERSION_INFO_BYTES + i] = (uint8_t) ( wrong >> ( i * 8 ) );
        }

        void * result = netcode_read_packet( buffer, bytes, &sequence, packet_key, GOLDEN_PROTOCOL_ID, current_timestamp, 0, UINT64_MAX, token_key, allowed_packets, NULL, NULL, NULL );
        printf( "7 %s %lu 0\n", result ? "request" : "refused", (unsigned long) sequence );
        if ( result )
            free( result );
    }

    return 1;
}

/*
    The receive-drain differential (subcommand "drain"). The same scripted
    receive queues run through this C reference here and through the C# port
    (compat/Compat.cs "drain"); scripts/interop.sh diffs the two transcripts
    byte for byte. Both sides print one line per queue and side:

        <queue> <server|client> consumed <n> processed <m>

    plus the four classifier rows. Queue values: > 0 is a junk datagram of
    that byte length, -1 is skip (an empty datagram or a receive error),
    0 is would-block (nothing more). Override transports only, time passed
    in, no sockets, no clock.

    NOTE: the override transport config field names below follow the C
    reference surface (sprint/netcode-audit-fixes, merge 7cd5f513):
    override_send_and_receive, send_packet_override(_context),
    receive_packet_override(_context). This leg builds against the netcode
    checkout given to scripts/interop.sh and is skipped when none is given.
*/

struct drain_script_t
{
    const int * entries;
    int num_entries;
    int index;
    int consumed;
    int processed;
};

static void drain_send_override( void * context, struct netcode_address_t * to, const uint8_t * packet_data, int packet_bytes )
{
    (void) context; (void) to; (void) packet_data; (void) packet_bytes;
}

static int drain_receive_override( void * context, struct netcode_address_t * from, uint8_t * buffer, int buffer_bytes )
{
    struct drain_script_t * script = (struct drain_script_t *) context;
    int result = script->index < script->num_entries ? script->entries[script->index] : 0;
    int i;
    (void) buffer_bytes;
    script->index++;
    script->consumed++;
    if ( result > 0 )
    {
        script->processed++;
        for ( i = 0; i < result; i++ )
            buffer[i] = 0xFF;
        netcode_parse_address( "203.0.113.7:12345", from );
    }
    return result;
}

static int * drain_junk_queue( int count )
{
    int * entries = (int *) malloc( sizeof( int ) * (size_t) count );
    int i;
    for ( i = 0; i < count; i++ )
        entries[i] = 11;
    return entries;
}

static void drain_server( const char * queue_name, const int * entries, int num_entries )
{
    struct drain_script_t script;
    struct netcode_server_config_t config;
    struct netcode_server_t * server;

    netcode_default_server_config( &config );
    config.protocol_id = SESSION_PROTOCOL_ID;
    memcpy( config.private_key, session_private_key, NETCODE_KEY_BYTES );
    config.override_send_and_receive = 1;
    config.send_packet_override = drain_send_override;
    config.callback_context = &script;
    config.receive_packet_override = drain_receive_override;

    memset( &script, 0, sizeof( script ) );
    script.entries = entries;
    script.num_entries = num_entries;

    server = netcode_server_create( "127.0.0.1:40000", &config, 0.0 );
    netcode_server_start( server, 1 );
    netcode_server_update( server, 1.0 );
    printf( "%s server consumed %d processed %d\n", queue_name, script.consumed, script.processed );
    netcode_server_destroy( server );
}

static void drain_client( const char * queue_name, const int * entries, int num_entries )
{
    struct drain_script_t script;
    struct netcode_client_config_t config;
    struct netcode_client_t * client;

    netcode_default_client_config( &config );
    config.override_send_and_receive = 1;
    config.send_packet_override = drain_send_override;
    config.callback_context = &script;
    config.receive_packet_override = drain_receive_override;

    memset( &script, 0, sizeof( script ) );
    script.entries = entries;
    script.num_entries = num_entries;

    client = netcode_client_create( "0.0.0.0:0", &config, 0.0 );
    netcode_client_update( client, 1.0 );
    printf( "%s client consumed %d processed %d\n", queue_name, script.consumed, script.processed );
    netcode_client_destroy( client );
}

static int do_drain( void )
{
    /* [junk, EMPTY, junk, junk] */
    {
        int entries[4] = { 11, -1, 11, 11 };
        drain_server( "q1", entries, 4 );
        drain_client( "q1", entries, 4 );
    }

    /* [EMPTY, EMPTY, EMPTY, junk] */
    {
        int entries[4] = { -1, -1, -1, 11 };
        drain_server( "q2", entries, 4 );
        drain_client( "q2", entries, 4 );
    }

    /* MAX_RECEIVE_PACKETS + 10 junk datagrams */
    {
        int * server_entries = drain_junk_queue( NETCODE_SERVER_MAX_RECEIVE_PACKETS + 10 );
        int * client_entries = drain_junk_queue( NETCODE_CLIENT_MAX_RECEIVE_PACKETS + 10 );
        drain_server( "q3", server_entries, NETCODE_SERVER_MAX_RECEIVE_PACKETS + 10 );
        drain_client( "q3", client_entries, NETCODE_CLIENT_MAX_RECEIVE_PACKETS + 10 );
        free( server_entries );
        free( client_entries );
    }

    /* a queue that ends with a would-block */
    {
        int entries[3] = { 11, 11, 0 };
        drain_server( "q4", entries, 3 );
        drain_client( "q4", entries, 3 );
    }

    /* classifier rows (netcode_classify_receive_result) */
    netcode_log_level( NETCODE_LOG_LEVEL_NONE );
    printf( "classify (0,0) -> %d\n", netcode_classify_receive_result( 0, 0, 0 ) );
    printf( "classify (-1,wouldblock) -> %d\n", netcode_classify_receive_result( -1, EAGAIN, 1 ) );
    printf( "classify (-1,other) -> %d\n", netcode_classify_receive_result( -1, ECONNREFUSED, 0 ) );
    printf( "classify (5,0) -> %d\n", netcode_classify_receive_result( 5, 0, 0 ) );

    return 1;
}

/* Mapping-bound challenge oracle. All token and packet inputs use fixed bytes;
   read_and_process_packet receives an explicit timestamp and the override
   transport captures the challenge without sockets or a wall-clock read. */
static uint8_t scenario_sent[NETCODE_MAX_PACKET_BYTES];
static int scenario_sent_bytes;

static void scenario_send( void * context, struct netcode_address_t * to, NETCODE_CONST uint8_t * data, int bytes )
{
    (void) context;
    (void) to;
    memcpy( scenario_sent, data, bytes );
    scenario_sent_bytes = bytes;
}

static int scenario_receive( void * context, struct netcode_address_t * from, uint8_t * data, int max_bytes )
{
    (void) context;
    (void) from;
    (void) data;
    (void) max_bytes;
    return 0;
}

static void scenario_token( struct netcode_connect_token_t * token, uint64_t id, uint8_t user, uint8_t seed )
{
    struct netcode_connect_token_private_t private_token;
    memset( &private_token, 0, sizeof( private_token ) );
    private_token.client_id = id;
    private_token.timeout_seconds = 15;
    private_token.num_server_addresses = 1;
    netcode_parse_address( "127.0.0.1:40000", &private_token.server_addresses[0] );
    fill_pattern( private_token.client_to_server_key, NETCODE_KEY_BYTES, 10 * seed );
    fill_pattern( private_token.server_to_client_key, NETCODE_KEY_BYTES, 10 * seed + 1 );
    memset( private_token.user_data, user, NETCODE_USER_DATA_BYTES );

    memset( token, 0, sizeof( *token ) );
    memcpy( token->version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
    token->protocol_id = SESSION_PROTOCOL_ID;
    token->create_timestamp = 1000;
    token->expire_timestamp = 1030;
    fill_pattern( token->nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES, 10 * seed + 2 );
    netcode_write_connect_token_private( &private_token, token->private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
    if ( netcode_encrypt_connect_token_private( token->private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES,
                                               token->version_info, token->protocol_id, token->expire_timestamp,
                                               token->nonce, session_private_key ) != NETCODE_OK )
        abort();
    token->timeout_seconds = 15;
    token->num_server_addresses = 1;
    token->server_addresses[0] = private_token.server_addresses[0];
    memcpy( token->client_to_server_key, private_token.client_to_server_key, NETCODE_KEY_BYTES );
    memcpy( token->server_to_client_key, private_token.server_to_client_key, NETCODE_KEY_BYTES );
}

static void scenario_process( struct netcode_server_t * server, struct netcode_address_t * from,
                              void * packet, uint64_t sequence, uint8_t * key, double logical_time,
                              const char * input_dir, const char * name )
{
    uint8_t wire[NETCODE_MAX_PACKET_BYTES];
    int bytes = netcode_write_packet( packet, wire, sizeof( wire ), sequence, key, SESSION_PROTOCOL_ID );
    if ( input_dir && !write_file( input_dir, name, wire, bytes ) ) abort();
    uint8_t allowed[NETCODE_CONNECTION_NUM_PACKETS] = { 0 };
    allowed[NETCODE_CONNECTION_REQUEST_PACKET] = 1;
    allowed[NETCODE_CONNECTION_RESPONSE_PACKET] = 1;
    server->time = logical_time;
    netcode_server_read_and_process_packet( server, from, wire, bytes, 1001, allowed );
}

static void scenario_request( struct netcode_server_t * server, struct netcode_address_t * from,
                              struct netcode_connect_token_t * token, double logical_time,
                              const char * input_dir, const char * name )
{
    struct netcode_connection_request_packet_t packet;
    memset( &packet, 0, sizeof( packet ) );
    packet.packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
    memcpy( packet.version_info, token->version_info, NETCODE_VERSION_INFO_BYTES );
    packet.protocol_id = token->protocol_id;
    packet.connect_token_expire_timestamp = token->expire_timestamp;
    memcpy( packet.connect_token_nonce, token->nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES );
    memcpy( packet.connect_token_data, token->private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
    scenario_process( server, from, &packet, 0, token->client_to_server_key, logical_time, input_dir, name );
}

static struct netcode_connection_challenge_packet_t scenario_challenge( struct netcode_connect_token_t * token )
{
    uint8_t wire[NETCODE_MAX_PACKET_BYTES];
    memcpy( wire, scenario_sent, scenario_sent_bytes );
    uint64_t sequence = 0;
    uint8_t allowed[NETCODE_CONNECTION_NUM_PACKETS] = { 0 };
    allowed[NETCODE_CONNECTION_CHALLENGE_PACKET] = 1;
    struct netcode_connection_challenge_packet_t * packet = netcode_read_packet(
        wire, scenario_sent_bytes, &sequence, token->server_to_client_key, SESSION_PROTOCOL_ID,
        1001, 0, UINT64_MAX, NULL, allowed, NULL, NULL, NULL );
    if ( !packet ) abort();
    struct netcode_connection_challenge_packet_t result = *packet;
    free( packet );
    return result;
}

static void scenario_write_challenge( const char * dir, const char * name,
                                      struct netcode_connection_challenge_packet_t * challenge )
{
    uint8_t data[8 + NETCODE_CHALLENGE_TOKEN_BYTES];
    uint8_t * p = data;
    netcode_write_uint64( &p, challenge->challenge_token_sequence );
    memcpy( p, challenge->challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );
    if ( !write_file( dir, name, data, sizeof( data ) ) ) abort();
}

static void scenario_response( struct netcode_server_t * server, struct netcode_address_t * from,
                               struct netcode_connect_token_t * token,
                               struct netcode_connection_challenge_packet_t * challenge,
                               uint64_t sequence, double logical_time,
                               const char * input_dir, const char * name )
{
    struct netcode_connection_response_packet_t packet;
    memset( &packet, 0, sizeof( packet ) );
    packet.packet_type = NETCODE_CONNECTION_RESPONSE_PACKET;
    packet.challenge_token_sequence = challenge->challenge_token_sequence;
    memcpy( packet.challenge_token_data, challenge->challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );
    scenario_process( server, from, &packet, sequence, token->client_to_server_key, logical_time, input_dir, name );
}

static void scenario_print( char const * step, struct netcode_server_t * server )
{
    uint64_t ids[NETCODE_MAX_CLIENTS];
    uint8_t users[NETCODE_MAX_CLIENTS];
    int count = 0;
    for ( int i = 0; i < netcode_server_max_clients( server ); i++ )
        if ( netcode_server_client_connected( server, i ) )
        {
            ids[count] = netcode_server_client_id( server, i );
            users[count] = ((uint8_t*) netcode_server_client_user_data( server, i ))[0];
            count++;
        }
    for ( int i = 0; i < count; i++ )
        for ( int j = i + 1; j < count; j++ )
            if ( ids[j] < ids[i] )
            {
                uint64_t id = ids[i]; ids[i] = ids[j]; ids[j] = id;
                uint8_t user = users[i]; users[i] = users[j]; users[j] = user;
            }
    printf( "%s connected ", step );
    if ( count == 0 ) printf( "-" );
    for ( int i = 0; i < count; i++ ) printf( "%s%04llx", i ? "," : "", (unsigned long long) ids[i] );
    printf( " userdata " );
    if ( count == 0 ) printf( "-" );
    for ( int i = 0; i < count; i++ ) printf( "%s%02x", i ? "," : "", users[i] );
    printf( "\n" );
}

static int do_challenge_mapping( const char * input_dir )
{
    struct netcode_server_config_t config;
    netcode_default_server_config( &config );
    config.protocol_id = SESSION_PROTOCOL_ID;
    config.override_send_and_receive = 1;
    config.send_packet_override = scenario_send;
    config.receive_packet_override = scenario_receive;
    memcpy( config.private_key, session_private_key, NETCODE_KEY_BYTES );
    struct netcode_server_t * server = netcode_server_create( "127.0.0.1:40000", &config, 0.0 );
    if ( !server ) return 0;
    netcode_server_start( server, 4 );
    fill_pattern( server->challenge_key, NETCODE_KEY_BYTES, 77 );
    server->min_connect_token_expire_timestamp = 1000;
    struct netcode_address_t x, y;
    netcode_parse_address( "127.0.0.1:50000", &x );
    netcode_parse_address( "127.0.0.1:50001", &y );
    struct netcode_connect_token_t a, b, c;
    scenario_token( &a, 0x1111, 0xa1, 1 );
    scenario_token( &b, 0x2222, 0xb2, 2 );
    scenario_token( &c, 0x3333, 0xc3, 3 );

    uint8_t token_bytes[NETCODE_CONNECT_TOKEN_BYTES];
    netcode_write_connect_token( &a, token_bytes, sizeof( token_bytes ) );
    if ( !write_file( input_dir, "token-a.bin", token_bytes, sizeof( token_bytes ) ) ) return 0;
    netcode_write_connect_token( &b, token_bytes, sizeof( token_bytes ) );
    if ( !write_file( input_dir, "token-b.bin", token_bytes, sizeof( token_bytes ) ) ) return 0;
    netcode_write_connect_token( &c, token_bytes, sizeof( token_bytes ) );
    if ( !write_file( input_dir, "token-c.bin", token_bytes, sizeof( token_bytes ) ) ) return 0;

    scenario_request( server, &x, &a, 0.0, input_dir, "01-request-A.bin" );
    struct netcode_connection_challenge_packet_t challenge_a = scenario_challenge( &a );
    scenario_write_challenge( input_dir, "challenge-A.bin", &challenge_a );
    scenario_print( "request-A", server );
    scenario_request( server, &y, &b, 0.1, input_dir, "02-request-B.bin" );
    struct netcode_connection_challenge_packet_t challenge_b = scenario_challenge( &b );
    scenario_write_challenge( input_dir, "challenge-B.bin", &challenge_b );
    scenario_print( "request-B", server );
    scenario_response( server, &y, &b, &challenge_a, 1, 0.2, input_dir, "03-response-Y-A.bin" );
    scenario_print( "response-Y-A", server );
    scenario_response( server, &y, &b, &challenge_b, 2, 0.3, input_dir, "04-response-Y-B.bin" );
    scenario_print( "response-Y-B", server );
    scenario_request( server, &x, &c, 0.4, input_dir, "05-request-C1.bin" );
    struct netcode_connection_challenge_packet_t challenge_c_first = scenario_challenge( &c );
    scenario_write_challenge( input_dir, "challenge-C1.bin", &challenge_c_first );
    scenario_print( "request-C1", server );
    scenario_request( server, &x, &c, 0.5, input_dir, "06-request-C2.bin" );
    struct netcode_connection_challenge_packet_t challenge_c_second = scenario_challenge( &c );
    scenario_write_challenge( input_dir, "challenge-C2.bin", &challenge_c_second );
    if ( challenge_c_second.challenge_token_sequence == challenge_c_first.challenge_token_sequence ) abort();
    scenario_print( "request-C2", server );
    scenario_response( server, &x, &c, &challenge_a, 1, 0.6, input_dir, "07-response-X-A.bin" );
    scenario_print( "response-X-A", server );
    scenario_response( server, &x, &c, &challenge_c_first, 2, 0.7, input_dir, "08-response-X-C1.bin" );
    scenario_print( "response-X-C1", server );
    netcode_server_destroy( server );
    return 1;
}

struct reentry_case_t
{
    struct netcode_server_t * server;
    const char * name;
    int callbacks;
    int reason;
    uint64_t id;
    uint8_t user;
};

static void reentry_callback( void * context, int slot, int connected )
{
    struct reentry_case_t * state = (struct reentry_case_t * ) context;
    if ( connected ) return;
    state->callbacks++;
    if ( state->callbacks != 1 ) return;
    state->reason = netcode_server_client_disconnect_reason( state->server, slot );
    state->id = netcode_server_client_id( state->server, slot );
    state->user = ( (const uint8_t *) netcode_server_client_user_data( state->server, slot ) )[0];
    if ( strcmp( state->name, "same" ) == 0 ) netcode_server_disconnect_client( state->server, slot );
    else if ( strcmp( state->name, "loopback" ) == 0 ) netcode_server_disconnect_loopback_client( state->server, slot );
    else netcode_server_stop( state->server );
}

static void reentry_loopback_send( void * context, int slot, const uint8_t * data, int bytes, uint64_t sequence )
{
    (void) context; (void) slot; (void) data; (void) bytes; (void) sequence;
}

static int do_disconnect_reentry( const char * input_dir )
{
    const char * names[] = { "same", "stop", "timeout", "loopback" };
    netcode_log_level( NETCODE_LOG_LEVEL_NONE );
    for ( int i = 0; i < 4; i++ )
    {
        struct reentry_case_t state;
        memset( &state, 0, sizeof( state ) );
        state.name = names[i];
        struct netcode_server_config_t config;
        netcode_default_server_config( &config );
        config.protocol_id = SESSION_PROTOCOL_ID;
        config.override_send_and_receive = 1;
        config.send_packet_override = scenario_send;
        config.receive_packet_override = scenario_receive;
        config.send_loopback_packet_callback = reentry_loopback_send;
        config.connect_disconnect_callback = reentry_callback;
        config.callback_context = &state;
        memcpy( config.private_key, session_private_key, NETCODE_KEY_BYTES );
        state.server = netcode_server_create( "127.0.0.1:40000", &config, 0.0 );
        if ( !state.server ) return 0;
        netcode_server_start( state.server, 1 );
        if ( strcmp( state.name, "loopback" ) == 0 )
        {
            uint8_t user[NETCODE_USER_DATA_BYTES];
            memset( user, 0, sizeof( user ) );
            user[0] = 0x5a;
            netcode_server_connect_loopback_client( state.server, 0, 0x1111, user );
        }
        else
        {
            fill_pattern( state.server->challenge_key, NETCODE_KEY_BYTES, 77 );
            state.server->min_connect_token_expire_timestamp = 1000;
            struct netcode_address_t from;
            netcode_parse_address( "127.0.0.1:50000", &from );
            struct netcode_connect_token_t token;
            scenario_token( &token, 0x1111, 0x5a, 1 );
            char path[64];
            snprintf( path, sizeof( path ), "%s-request.bin", state.name );
            scenario_request( state.server, &from, &token, 0.0, input_dir, path );
            struct netcode_connection_challenge_packet_t challenge = scenario_challenge( &token );
            snprintf( path, sizeof( path ), "%s-response.bin", state.name );
            scenario_response( state.server, &from, &token, &challenge, 1, 0.1, input_dir, path );
            if ( !state.server->client_connected[0] ) return 0;
        }
        if ( strcmp( state.name, "loopback" ) == 0 ) netcode_server_disconnect_loopback_client( state.server, 0 );
        else if ( strcmp( state.name, "timeout" ) == 0 ) netcode_server_update( state.server, 16.2 );
        else netcode_server_disconnect_client( state.server, 0 );
        printf( "%s callbacks %d saw %d %" PRIu64 " %u connected %d mappings %d slot %s\n",
                state.name, state.callbacks, state.reason, state.id, state.user,
                state.server->num_connected_clients, state.server->encryption_manager.num_encryption_mappings,
                state.server->client_connected[0] ? "connected" : "clear" );
        if ( strcmp( state.name, "stop" ) == 0 ) netcode_server_start( state.server, 1 );
        netcode_server_destroy( state.server );
    }
    return 1;
}

/*
    Global nonce differential (subcommand "nonces"). Two servers started from
    fresh, then one stopped and started again, plus a client that connects,
    disconnects and connects with the same token. Prints only boolean properties
    of the global sequence and the client state name. Never prints the random
    sequence values. scripts/interop.sh diffs this against compat/Compat.cs.
*/

static void nonce_send_override( void * context, struct netcode_address_t * to, const uint8_t * packet_data, int packet_bytes )
{
    (void) context;
    (void) to;
    (void) packet_data;
    (void) packet_bytes;
}

static int nonce_receive_override( void * context, struct netcode_address_t * from, uint8_t * buffer, int buffer_bytes )
{
    (void) context;
    (void) from;
    (void) buffer;
    (void) buffer_bytes;
    return 0;
}

static int do_nonces( void )
{
    struct netcode_server_config_t server_config;
    struct netcode_client_config_t client_config;
    struct netcode_server_t * server_a;
    struct netcode_server_t * server_b;
    struct netcode_client_t * client;
    NETCODE_CONST char * server_address = "127.0.0.1:40000";
    uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];
    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    uint64_t floor = 1ULL << 63;
    uint64_t first;

    netcode_log_level( NETCODE_LOG_LEVEL_NONE );

    netcode_default_server_config( &server_config );
    server_config.protocol_id = SESSION_PROTOCOL_ID;
    memcpy( server_config.private_key, session_private_key, NETCODE_KEY_BYTES );
    server_config.override_send_and_receive = 1;
    server_config.send_packet_override = nonce_send_override;
    server_config.receive_packet_override = nonce_receive_override;

    server_a = netcode_server_create( "127.0.0.1:40000", &server_config, 0.0 );
    server_b = netcode_server_create( "127.0.0.1:40001", &server_config, 0.0 );
    if ( !server_a || !server_b )
        return 0;

    netcode_server_start( server_a, 1 );
    netcode_server_start( server_b, 1 );
    first = server_a->global_sequence;
    printf( "fresh a-ge %d\n", server_a->global_sequence >= floor ? 1 : 0 );
    printf( "fresh b-ge %d\n", server_b->global_sequence >= floor ? 1 : 0 );
    printf( "fresh differ %d\n", server_a->global_sequence != server_b->global_sequence ? 1 : 0 );

    netcode_server_stop( server_a );
    netcode_server_start( server_a, 1 );
    printf( "restart ge %d\n", server_a->global_sequence >= floor ? 1 : 0 );
    printf( "restart differ %d\n", server_a->global_sequence != first ? 1 : 0 );

    netcode_server_destroy( server_a );
    netcode_server_destroy( server_b );

    netcode_default_client_config( &client_config );
    client_config.override_send_and_receive = 1;
    client_config.send_packet_override = nonce_send_override;
    client_config.receive_packet_override = nonce_receive_override;
    client = netcode_client_create( "127.0.0.1:50000", &client_config, 0.0 );
    if ( !client )
        return 0;

    memset( user_data, 1, NETCODE_USER_DATA_BYTES );
    if ( netcode_generate_connect_token( 1, &server_address, &server_address, 30, 15, 1, SESSION_PROTOCOL_ID, session_private_key, user_data, connect_token ) != NETCODE_OK )
        return 0;

    netcode_client_connect( client, connect_token );
    netcode_client_disconnect( client );
    netcode_client_connect( client, connect_token );
    printf( "client reuse %s\n", netcode_client_state_name( netcode_client_state( client ) ) );
    netcode_client_destroy( client );
    return 1;
}

static int do_token_lifetimes( void )
{
    netcode_log_level( NETCODE_LOG_LEVEL_NONE );
    struct netcode_server_config_t config;
    netcode_default_server_config( &config );
    config.protocol_id = SESSION_PROTOCOL_ID;
    config.override_send_and_receive = 1;
    config.send_packet_override = scenario_send;
    config.receive_packet_override = scenario_receive;
    memcpy( config.private_key, session_private_key, NETCODE_KEY_BYTES );
    struct netcode_server_t * server = netcode_server_create( "127.0.0.1:40000", &config, 0.0 );
    if ( !server ) return 0;
    netcode_server_start( server, 4 );
    server->min_connect_token_expire_timestamp = 1000;
    struct netcode_address_t x;
    netcode_parse_address( "127.0.0.1:50000", &x );

    int timeouts[] = { -1, 0, 1, 5, 30 };
    for ( int i = 0; i < 5; i++ )
    {
        struct netcode_connect_token_t token;
        scenario_token( &token, 0x1111, 0xa1, 1 );
        struct netcode_connect_token_private_t private_token;
        if ( netcode_decrypt_connect_token_private( token.private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES,
                token.version_info, token.protocol_id, token.expire_timestamp, token.nonce, session_private_key ) != NETCODE_OK ) return 0;
        if ( netcode_read_connect_token_private( token.private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, &private_token ) != NETCODE_OK ) return 0;
        private_token.timeout_seconds = timeouts[i];
        netcode_write_connect_token_private( &private_token, token.private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
        if ( netcode_encrypt_connect_token_private( token.private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES,
                token.version_info, token.protocol_id, token.expire_timestamp, token.nonce, session_private_key ) != NETCODE_OK ) return 0;
        token.timeout_seconds = timeouts[i];
        scenario_request( server, &x, &token, 0.0, NULL, NULL );
        int offset = -1;
        for ( int t = 0; t <= 40; t++ )
        {
            netcode_server_update( server, (double) t );
            int active = 0;
            for ( int j = 0; j < server->encryption_manager.num_encryption_mappings; j++ )
                if ( server->encryption_manager.address[j].type != NETCODE_ADDRESS_NONE &&
                     !netcode_encryption_manager_entry_expired( &server->encryption_manager, j, (double) t ) )
                    active++;
            if ( active == 0 ) { offset = t; break; }
        }
        if ( offset < 0 ) printf( "timeout %d -> never\n", timeouts[i] );
        else printf( "timeout %d -> %d\n", timeouts[i], offset );
        netcode_server_stop( server );
        netcode_server_start( server, 4 );
        server->min_connect_token_expire_timestamp = 1000;

        scenario_request( server, &x, &token, 0.0, NULL, NULL );
        struct netcode_connection_challenge_packet_t challenge = scenario_challenge( &token );
        netcode_server_update( server, 0.1 );
        scenario_response( server, &x, &token, &challenge, 1, 0.1, NULL, NULL );
        printf( "response %d -> %s\n", timeouts[i], server->num_connected_clients == 1 ? "connects" : "refused" );
        netcode_server_stop( server );
        netcode_server_start( server, 4 );
        server->min_connect_token_expire_timestamp = 1000;
    }

    const uint64_t expiries[] = { UINT64_MAX, 1060, 1031, 1030, 1030, 1001, 1000 };
    const uint64_t floors[] = { 1000, 1000, 1000, 1000, 1030, 1000, 1000 };
    const char * expiry_names[] = { "max", "plus60", "plus31", "plus30", "floor", "plus1", "expired" };
    for ( int i = 0; i < 7; i++ )
    {
        struct netcode_connect_token_t token;
        scenario_token( &token, 0x1111, 0xa1, 1 );
        if ( netcode_decrypt_connect_token_private( token.private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES,
                token.version_info, token.protocol_id, token.expire_timestamp, token.nonce, session_private_key ) != NETCODE_OK ) return 0;
        token.expire_timestamp = expiries[i];
        if ( netcode_encrypt_connect_token_private( token.private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES,
                token.version_info, token.protocol_id, token.expire_timestamp, token.nonce, session_private_key ) != NETCODE_OK ) return 0;
        struct netcode_connection_request_packet_t request;
        memset( &request, 0, sizeof( request ) );
        request.packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
        memcpy( request.version_info, token.version_info, NETCODE_VERSION_INFO_BYTES );
        request.protocol_id = token.protocol_id;
        request.connect_token_expire_timestamp = token.expire_timestamp;
        memcpy( request.connect_token_nonce, token.nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES );
        memcpy( request.connect_token_data, token.private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
        uint8_t wire[NETCODE_MAX_PACKET_BYTES];
        int bytes = netcode_write_packet( &request, wire, sizeof( wire ), 0, token.client_to_server_key, SESSION_PROTOCOL_ID );
        uint64_t sequence = 0;
        uint8_t allowed[NETCODE_CONNECTION_NUM_PACKETS] = { 0 };
        allowed[NETCODE_CONNECTION_REQUEST_PACKET] = 1;
        void * packet = netcode_read_packet( wire, bytes, &sequence, NULL, SESSION_PROTOCOL_ID,
            1000, floors[i], 30, session_private_key, allowed, NULL, NULL, NULL );
        printf( "expiry %s -> %s\n", expiry_names[i], packet ? "accepted" : "refused" );
        free( packet );
    }
    netcode_server_destroy( server );
    return 1;
}

static int do_client_address( void )
{
    netcode_log_level( NETCODE_LOG_LEVEL_NONE );
    struct netcode_client_config_t config;
    netcode_default_client_config( &config );
    config.override_send_and_receive = 1;
    config.send_packet_override = scenario_send;
    config.receive_packet_override = scenario_receive;
    struct netcode_client_t * client = netcode_client_create( "0.0.0.0:50000", &config, 0.0 );
    if ( !client ) return 0;
    // The nonzero handle is only an in-memory family marker. Override transport
    // remains on outside the two direct address-selection calls.
    client->socket_holder.ipv4.handle = 1;

    const char * lists[4][2] = { { "[::1]:40000", NULL }, { "[::1]:40000", "127.0.0.1:40000" },
                                { "127.0.0.1:40000", NULL }, { "127.0.0.1:40000", "[::1]:40000" } };
    const char * names[4] = { "v6", "v6v4", "v4", "v4v6" };
    for ( int i = 0; i < 4; i++ )
    {
        uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];
        struct netcode_connect_token_t token;
        scenario_token( &token, 0x1111, 0xa1, (uint8_t) ( i + 1 ) );
        int num = lists[i][1] ? 2 : 1;
        token.num_server_addresses = num;
        for ( int j = 0; j < num; j++ )
            if ( netcode_parse_address( lists[i][j], &token.server_addresses[j] ) != NETCODE_OK ) return 0;
        netcode_write_connect_token( &token, connect_token, sizeof( connect_token ) );
        netcode_client_disconnect( client );
        client->config.override_send_and_receive = 0;
        netcode_client_connect( client, connect_token );
        client->config.override_send_and_receive = 1;
        if ( i == 3 )
        {
            client->config.override_send_and_receive = 0;
            if ( !netcode_client_connect_to_next_server( client ) ) return 0;
            client->config.override_send_and_receive = 1;
        }
        int state = netcode_client_state( client );
        printf( "%s state %s address %s\n", names[i], netcode_client_state_name( state ),
                state == NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST ?
                    ( client->server_address_index == 1 ? "1" : "0" ) : "none" );
    }
    client->socket_holder.ipv4.handle = 0;
    netcode_client_destroy( client );
    return 1;
}

int main( int argc, char ** argv )
{
    if ( netcode_init() != NETCODE_OK )
    {
        printf( "error: failed to initialize netcode\n" );
        return 1;
    }

    netcode_log_level( NETCODE_LOG_LEVEL_ERROR );

    int ok = 0;

    if ( argc == 3 && strcmp( argv[1], "goldens" ) == 0 )
        ok = do_goldens( argv[2] );
    else if ( argc == 3 && strcmp( argv[1], "verify" ) == 0 )
        ok = do_verify( argv[2] );
    else if ( argc == 4 && strcmp( argv[1], "mint" ) == 0 )
        ok = do_mint( argv[2], argv[3] );
    else if ( argc == 3 && strcmp( argv[1], "server" ) == 0 )
        ok = do_server( atoi( argv[2] ) );
    else if ( argc == 4 && strcmp( argv[1], "client" ) == 0 )
        ok = do_client( atoi( argv[2] ), argv[3] );
    else if ( argc == 2 && strcmp( argv[1], "diffpackets" ) == 0 )
        ok = do_diff_packets();
    else if ( argc == 2 && strcmp( argv[1], "drain" ) == 0 )
        ok = do_drain();
    else if ( argc == 2 && strcmp( argv[1], "nonces" ) == 0 )
        ok = do_nonces();
    else if ( argc == 3 && strcmp( argv[1], "challenge-mapping" ) == 0 )
        ok = do_challenge_mapping( argv[2] );
    else if ( argc == 3 && strcmp( argv[1], "disconnect-reentry" ) == 0 )
        ok = do_disconnect_reentry( argv[2] );
    else if ( argc == 2 && strcmp( argv[1], "token-lifetimes" ) == 0 )
        ok = do_token_lifetimes();
    else if ( argc == 2 && strcmp( argv[1], "client-address" ) == 0 )
        ok = do_client_address();
    else
        printf( "usage: compat-c goldens <dir> | verify <dir> | mint <file> <address> | server <port> | client <port> <token> | diffpackets | drain | nonces\n" );

    netcode_term();

    return ok ? 0 : 1;
}
