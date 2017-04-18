//
//  stream.c
//  Crypto
//
//  Created by Tom Leavy on 4/11/17.
//
//

#include "stream.h"
#include "memory.h"
#include "stream.pb-c.h"
#include "protobuf_util.h"

struct wickr_stream {
    
    wickr_crypto_engine_t *engine;
    wickr_node_t *local_identity;
    wickr_node_t *remote_identity;
    wickr_buffer_t *iv_seed;
    wickr_cipher_key_t *tx_key;
    wickr_cipher_key_t *rx_key;
    uint64_t rx_seq;
    uint64_t tx_seq;
    wickr_stream_status status;
    
};

typedef enum { WICKR_HANDSHAKE_PHASE_INIT, WICKR_HANDSHAKE_PHASE_RESPONSE, WICKR_HANDSHAKE_PHASE_FINALIZE } wickr_handshake_phase;

wickr_stream_t *wickr_stream_create(wickr_crypto_engine_t *engine, wickr_node_t *local_identity, wickr_node_t *remote_identity)
{
    if (!engine || !local_identity || !remote_identity) {
        return NULL;
    }
    
    wickr_stream_t *stream = wickr_alloc_zero(sizeof(wickr_stream_t));
    
    if (!stream) {
        return NULL;
    }
    
    stream->status = STREAM_STATUS_NONE;
    stream->tx_seq = 0;
    stream->rx_seq = 0;
    
    stream->engine = engine;
    stream->local_identity = local_identity;
    stream->remote_identity = remote_identity;
    
    return stream;
    
}

wickr_stream_t *wickr_stream_copy(wickr_stream_t *stream)
{
    //TODO: Implement proper copy
    return NULL;
}

void wickr_stream_destroy(wickr_stream_t **stream)
{
    if (!stream || !*stream) {
        return;
    }
    
    wickr_node_destroy(&(*stream)->local_identity);
    wickr_node_destroy(&(*stream)->remote_identity);
    wickr_buffer_destroy(&(*stream)->iv_seed);
    wickr_cipher_key_destroy(&(*stream)->tx_key);
    wickr_cipher_key_destroy(&(*stream)->rx_key);
    
    wickr_free(*stream);
    *stream = NULL;
}

static wickr_packet_t *__wickr_handshake_packet_create(wickr_stream_t *stream, Wickr__Proto__Handshake *handshake)
{
    size_t packed_size = wickr__proto__handshake__get_packed_size(handshake);
    
    wickr_buffer_t *seed_buffer = wickr_buffer_create_empty(packed_size);
    
    if (!seed_buffer) {
        return NULL;
    }
    
    wickr__proto__handshake__pack(handshake, seed_buffer->bytes);
    
    wickr_ecdsa_result_t *signature = wickr_identity_sign(stream->local_identity->id_chain->node, stream->engine, seed_buffer);
    
    if (!signature) {
        wickr_buffer_destroy(&seed_buffer);
        return NULL;
    }
    
    wickr_packet_t *handshake_packet = wickr_packet_create(CURRENT_PACKET_VERSION, seed_buffer, signature);
    
    if (!handshake_packet) {
        wickr_buffer_destroy(&seed_buffer);
        wickr_ecdsa_result_destroy(&signature);
        return NULL;
    }
    
    return handshake_packet;
}

static Wickr__Proto__Handshake *__wickr_handshake_packet_unpack(wickr_stream_t *stream,
                                                                wickr_packet_t *packet,
                                                                Wickr__Proto__Handshake__PayloadCase expected_payload)
{
    if (!stream || !packet) {
        return NULL;
    }
    
    bool valid = stream->engine->wickr_crypto_engine_ec_verify(packet->signature,
                                                         stream->remote_identity->id_chain->node->sig_key,
                                                         packet->content);
    
    if (!valid) {
        return NULL;
    }
    
    Wickr__Proto__Handshake *handshake_data = wickr__proto__handshake__unpack(NULL, packet->content->bytes, packet->content->length);
    
    if (!handshake_data) {
        return NULL;
    }
    
    if (handshake_data->version != CURRENT_HANDSHAKE_VERSION ||
        handshake_data->payload_case != expected_payload)
    {
        wickr__proto__handshake__free_unpacked(handshake_data, NULL);
        return NULL;
    }
    
    return handshake_data;
}

static wickr_packet_t *__wickr_handshake_generate_tx_key_exchange(wickr_stream_t *stream,
                                                                  Wickr__Proto__Handshake__PayloadCase phase,
                                                                  wickr_cipher_key_t *tx_key,
                                                                  uint8_t version)
{
    if (!stream ||
        version != CURRENT_HANDSHAKE_VERSION ||
        phase == WICKR__PROTO__HANDSHAKE__PAYLOAD_SEED)
    {
        return NULL;
    }
    
    wickr_ec_key_t *packet_exchange_key = stream->engine->wickr_crypto_engine_ec_rand_key(stream->engine->default_curve);
    
    if (!packet_exchange_key) {
        return NULL;
    }
    
    if (!tx_key) {
        wickr_ec_key_destroy(&packet_exchange_key);
        return NULL;
    }
    
    wickr_key_exchange_t *key_exchange = wickr_key_exchange_create_from_components(stream->engine,
                                                                                   stream->local_identity->id_chain,
                                                                                   stream->remote_identity,
                                                                                   packet_exchange_key,
                                                                                   tx_key, version);
    
    if (!key_exchange) {
        wickr_ec_key_destroy(&packet_exchange_key);
        wickr_cipher_key_destroy(&tx_key);
        return NULL;
    }
    
    Wickr__Proto__Handshake__KeyExchange key_exchange_p = WICKR__PROTO__HANDSHAKE__KEY_EXCHANGE__INIT;
    key_exchange_p.has_sender_pub = true;
    key_exchange_p.sender_pub.data = packet_exchange_key->pub_data->bytes;
    key_exchange_p.sender_pub.len = packet_exchange_key->pub_data->length;
    key_exchange_p.has_exchange_data = true;
    key_exchange_p.exchange_data.data = key_exchange->exchange_data->bytes;
    key_exchange_p.exchange_data.len = key_exchange->exchange_data->length;
    
    Wickr__Proto__Handshake__Response response = WICKR__PROTO__HANDSHAKE__RESPONSE__INIT;
    response.key_exchange = &key_exchange_p;
    response.drop = false;
    
    Wickr__Proto__Handshake return_handshake = WICKR__PROTO__HANDSHAKE__INIT;
    return_handshake.payload_case = phase;
    return_handshake.response = &response;
    return_handshake.version = version;
    
    wickr_packet_t *packet = __wickr_handshake_packet_create(stream, &return_handshake);
    wickr_ec_key_destroy(&packet_exchange_key);
    wickr_key_exchange_destroy(&key_exchange);
    
    if (!packet) {
        wickr_cipher_key_destroy(&tx_key);
        return NULL;
    }
    
    return packet;
}

wickr_packet_t *wickr_stream_begin_handshake(wickr_stream_t *stream, uint8_t version)
{
    if (!stream || version != CURRENT_HANDSHAKE_VERSION) {
        return NULL;
    }
    
    wickr_ec_key_t *handshake_key = stream->engine->wickr_crypto_engine_ec_rand_key(stream->engine->default_curve);
    
    if (!handshake_key) {
        return NULL;
    }
    
    Wickr__Proto__Handshake__Seed seed = WICKR__PROTO__HANDSHAKE__SEED__INIT;
    seed.has_pubkey = true;
    seed.pubkey.data = handshake_key->pub_data->bytes;
    seed.pubkey.len = handshake_key->pub_data->length;
    
    Wickr__Proto__Handshake handshake = WICKR__PROTO__HANDSHAKE__INIT;
    handshake.payload_case = WICKR__PROTO__HANDSHAKE__PAYLOAD_SEED;
    handshake.seed = &seed;
    handshake.version = version;
    
    wickr_packet_t *handshake_pkt = __wickr_handshake_packet_create(stream, &handshake);
    
    if (!handshake_pkt) {
        wickr_ec_key_destroy(&handshake_key);
        return NULL;
    }
    
    wickr_ephemeral_keypair_t *ephemeral_key = wickr_ephemeral_keypair_create(0, handshake_key, NULL);
    
    if (!ephemeral_key) {
        wickr_ec_key_destroy(&handshake_key);
        return NULL;
    }
    
    if (!wickr_node_rotate_keypair(stream->local_identity, ephemeral_key, false)) {
        wickr_ephemeral_keypair_destroy(&ephemeral_key);
        return NULL;
    }
    
    return handshake_pkt;
}

static bool __wickr_handshake_update_remote_keypair(wickr_stream_t *stream, ProtobufCBinaryData pubkey_data)
{
    if (!stream) {
        return false;
    }
    
    wickr_buffer_t remote_keypair_buffer = { pubkey_data.len, pubkey_data.data };
    wickr_ec_key_t *remote_keypair = stream->engine->wickr_crypto_engine_ec_key_import(&remote_keypair_buffer, false);
    
    if (!remote_keypair) {
        return false;
    }
    
    wickr_ephemeral_keypair_t *remote_eph_keypair = wickr_ephemeral_keypair_create(0, remote_keypair, NULL);
    
    if (!remote_keypair) {
        wickr_ec_key_destroy(&remote_keypair);
        return false;
    }
    
    if (!wickr_node_rotate_keypair(stream->remote_identity, remote_eph_keypair, false)) {
        wickr_ephemeral_keypair_destroy(&remote_eph_keypair);
        return false;
    }
    
    return true;
}

static void __wickr_stream_update_tx_key(wickr_stream_t *stream, wickr_cipher_key_t *tx_key)
{
    wickr_cipher_key_destroy(&stream->tx_key);
    stream->tx_key = tx_key;
}

static void __wickr_stream_update_rx_key(wickr_stream_t *stream, wickr_cipher_key_t *rx_key)
{
    wickr_cipher_key_destroy(&stream->rx_key);
    stream->rx_key = rx_key;
}

static wickr_packet_t *__wickr_stream_handshake_respond(wickr_stream_t *stream, ProtobufCBinaryData pubkey_data, uint8_t version)
{
    if (!stream ) {
        return NULL;
    }
    
    if (!__wickr_handshake_update_remote_keypair(stream, pubkey_data)) {
        stream->status = STREAM_STATUS_ERROR;
        return NULL;
    }
    
    wickr_cipher_key_t *tx_key = stream->engine->wickr_crypto_engine_cipher_key_random(stream->engine->default_cipher);
    
    if (!tx_key) {
        wickr_ephemeral_keypair_destroy(&stream->remote_identity->ephemeral_keypair);
        stream->status = STREAM_STATUS_ERROR;
        return NULL;
    }
    
    Wickr__Proto__Handshake__PayloadCase phase = stream->status == STREAM_STATUS_NONE ? WICKR__PROTO__HANDSHAKE__PAYLOAD_RESPONSE : WICKR__PROTO__HANDSHAKE__PAYLOAD_FINISH;
    
    wickr_packet_t *packet = __wickr_handshake_generate_tx_key_exchange(stream,
                                                                        phase,
                                                                        tx_key,
                                                                        version);
    
    if (!packet) {
        wickr_ephemeral_keypair_destroy(&stream->remote_identity->ephemeral_keypair);
        wickr_cipher_key_destroy(&tx_key);
        stream->status = STREAM_STATUS_ERROR;
        return NULL;
    }
    
    __wickr_stream_update_tx_key(stream, tx_key);
    
    return packet;

}

wickr_packet_t *wickr_stream_handshake_seed_respond(wickr_stream_t *stream, wickr_packet_t *handshake, uint8_t version)
{
    if (!stream || !handshake || version != CURRENT_HANDSHAKE_VERSION || stream->status == STREAM_STATUS_ERROR) {
        return NULL;
    }
    
    Wickr__Proto__Handshake *handshake_data = __wickr_handshake_packet_unpack(stream, handshake, WICKR__PROTO__HANDSHAKE__PAYLOAD_SEED);
    
    if (!handshake_data) {
        stream->status = STREAM_STATUS_ERROR;
        return NULL;
    }
    
    if (!handshake_data->seed->has_pubkey) {
        wickr__proto__handshake__free_unpacked(handshake_data, NULL);
        stream->status = STREAM_STATUS_ERROR;
        return NULL;
    }
    
    wickr_packet_t *return_packet = __wickr_stream_handshake_respond(stream, handshake_data->seed->pubkey, version);
    wickr__proto__handshake__free_unpacked(handshake_data, NULL);
    
    if (!return_packet) {
        stream->status = STREAM_STATUS_ERROR;
    }
    else {
        stream->status = STREAM_STATUS_TX_INIT;
    }
    
    return return_packet;
}

static wickr_cipher_key_t *__wickr_stream_handshake_decode_rx_key(wickr_stream_t *stream, Wickr__Proto__Handshake__KeyExchange *return_exchange, uint8_t version)
{
    if (!stream || !return_exchange) {
        return NULL;
    }
    
    if (
        !return_exchange->has_exchange_data ||
        !return_exchange->has_sender_pub)
    {
        return NULL;
    }
    
    wickr_buffer_t key_exchange_buffer = { return_exchange->exchange_data.len, return_exchange->exchange_data.data };
    wickr_buffer_t exchange_key_buffer = { return_exchange->sender_pub.len, return_exchange->sender_pub.data };
    
    wickr_key_exchange_t exchange;
    exchange.ephemeral_key_id = 0;
    exchange.node_id = stream->local_identity->id_chain->node->identifier;
    exchange.exchange_data = &key_exchange_buffer;
    
    wickr_ec_key_t *ec_key = stream->engine->wickr_crypto_engine_ec_key_import(&exchange_key_buffer, false);
    
    if (!ec_key) {
        return NULL;
    }
    
    wickr_cipher_key_t *rx_key = wickr_key_exchange_derive_packet_key(stream->engine, stream->remote_identity->id_chain, stream->local_identity, ec_key, &exchange, version);
    
    wickr_ephemeral_keypair_destroy(&stream->local_identity->ephemeral_keypair);
    
    wickr_ec_key_destroy(&ec_key);

    return rx_key;
}

static Wickr__Proto__Handshake *__wickr_stream_handshake_process_response(wickr_stream_t *stream, wickr_packet_t *return_handshake)
{
    if (!stream || !return_handshake) {
        return NULL;
    }
    
    switch (stream->status) {
        case STREAM_STATUS_NONE:
        case STREAM_STATUS_ERROR:
        case STREAM_STATUS_ACTIVE:
            stream->status = STREAM_STATUS_ERROR;
            return NULL;
        default:
            break;
    }
    
    Wickr__Proto__Handshake__PayloadCase phase = stream->status == STREAM_STATUS_SEEDED ? WICKR__PROTO__HANDSHAKE__PAYLOAD_RESPONSE : WICKR__PROTO__HANDSHAKE__PAYLOAD_FINISH;
    
    Wickr__Proto__Handshake *handshake_data = __wickr_handshake_packet_unpack(stream,
                                                                              return_handshake,
                                                                              phase);
    
    if (!handshake_data) {
        stream->status = STREAM_STATUS_ERROR;
        return NULL;
    }
    
    Wickr__Proto__Handshake__KeyExchange *key_exchange;
    
    switch (phase) {
        case WICKR__PROTO__HANDSHAKE__PAYLOAD_RESPONSE:
            key_exchange = handshake_data->response->key_exchange;
            break;
        case WICKR__PROTO__HANDSHAKE__PAYLOAD_FINISH:
            key_exchange = handshake_data->finish->key_exchange;
            break;
        default:
            wickr__proto__handshake__free_unpacked(handshake_data, NULL);
            stream->status = STREAM_STATUS_ERROR;
            return NULL;
    }
   
    wickr_cipher_key_t *rx_key = __wickr_stream_handshake_decode_rx_key(stream, key_exchange, handshake_data->version);
    
    if (!rx_key) {
        wickr__proto__handshake__free_unpacked(handshake_data, NULL);
        stream->status = STREAM_STATUS_ERROR;
        return NULL;
    }
    
    __wickr_stream_update_rx_key(stream, rx_key);
    stream->status = STREAM_STATUS_ACTIVE;
    
    return handshake_data;
}

wickr_packet_t *wickr_stream_handshake_process_return(wickr_stream_t *stream, wickr_packet_t *return_handshake)
{
    if (!stream || !return_handshake || stream->status == STREAM_STATUS_ERROR) {
        stream->status = STREAM_STATUS_ERROR;
        return NULL;
    }
    
    Wickr__Proto__Handshake *handshake_data = __wickr_stream_handshake_process_response(stream, return_handshake);
    
    if (!handshake_data) {
        stream->status = STREAM_STATUS_ERROR;
        return NULL;
    }
    
    wickr_packet_t *return_packet = __wickr_stream_handshake_respond(stream, handshake_data->response->response_key->pubkey, handshake_data->version);
    wickr__proto__handshake__free_unpacked(handshake_data, NULL);
    
    if (!return_packet) {
        stream->status = STREAM_STATUS_ERROR;
    }
    
    return return_packet;

}

bool wickr_stream_handshake_finish(wickr_stream_t *stream, wickr_packet_t *finish_handshake)
{
    if (!stream || !finish_handshake || stream->status == STREAM_STATUS_ERROR) {
        return NULL;
    }
    
    Wickr__Proto__Handshake *handshake_data = __wickr_stream_handshake_process_response(stream, finish_handshake);
    
    if (!handshake_data) {
        wickr__proto__handshake__free_unpacked(handshake_data, NULL);
        stream->status = STREAM_STATUS_ERROR;
        return false;
    }
    
    wickr__proto__handshake__free_unpacked(handshake_data, NULL);

    return true;
}

