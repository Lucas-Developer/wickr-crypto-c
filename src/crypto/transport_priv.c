//
//  transport_priv.c
//  Crypto
//
//  Created by Tom Leavy on 5/10/17.
//
//

#include "transport_priv.h"
#include "memory.h"

wickr_transport_packet_t *wickr_transport_packet_create(uint64_t seq_num, wickr_transport_payload_type body_type, wickr_buffer_t *body, wickr_buffer_t *mac)
{
    if (!body) {
        return NULL;
    }
    
    wickr_transport_packet_t *transport_pkt = wickr_alloc_zero(sizeof(wickr_transport_packet_t));
    
    if (!transport_pkt) {
        return NULL;
    }
    
    transport_pkt->seq_num = seq_num;
    transport_pkt->body_type = body_type;
    transport_pkt->body = body;
    transport_pkt->mac = mac;
    
    return transport_pkt;
}

wickr_transport_packet_t *wickr_transport_packet_copy(wickr_transport_packet_t *pkt)
{
    if (!pkt) {
        return NULL;
    }
    
    wickr_buffer_t *body_copy = wickr_buffer_copy(pkt->body);
    
    if (!body_copy) {
        return NULL;
    }
    
    wickr_buffer_t *mac_copy = wickr_buffer_copy(pkt->mac);
    
    if (pkt->mac && !mac_copy) {
        wickr_buffer_destroy(&body_copy);
        return NULL;
    }
    
    wickr_transport_packet_t *copy = wickr_transport_packet_create(pkt->seq_num, pkt->body_type, body_copy, mac_copy);
    
    if (!copy) {
        wickr_buffer_destroy(&body_copy);
        wickr_buffer_destroy(&mac_copy);
        return NULL;
    }
    
    return copy;
}

void wickr_transport_packet_destroy(wickr_transport_packet_t **pkt)
{
    if (!pkt || !*pkt) {
        return;
    }
    
    wickr_buffer_destroy(&(*pkt)->body);
    wickr_buffer_destroy(&(*pkt)->mac);
    wickr_free(*pkt);
    *pkt = NULL;
}

wickr_buffer_t *wickr_transport_packet_make_meta_buffer(wickr_transport_packet_t *pkt)
{
    if (!pkt) {
        return NULL;
    }
    
    wickr_buffer_t seq_buffer;
    seq_buffer.length = sizeof(uint64_t);
    seq_buffer.bytes = (uint8_t *)&pkt->seq_num;
    
    wickr_buffer_t type_buffer;
    type_buffer.length = sizeof(uint8_t);
    type_buffer.bytes = (uint8_t *)&pkt->body_type;
    
    return wickr_buffer_concat(&seq_buffer, &type_buffer);
}

wickr_buffer_t *wickr_transport_packet_serialize(wickr_transport_packet_t *pkt)
{
    if (!pkt) {
        return NULL;
    }
    
    wickr_buffer_t *meta_buffer = wickr_transport_packet_make_meta_buffer(pkt);
    
    if (!meta_buffer) {
        return NULL;
    }
    
    wickr_buffer_t *components[] = { meta_buffer, pkt->body, pkt->mac };
    wickr_buffer_t *return_buffer = wickr_buffer_concat_multi(components, BUFFER_ARRAY_LEN(components));
    wickr_buffer_destroy(&meta_buffer);
    
    return return_buffer;
}

wickr_transport_packet_t *wickr_transport_packet_create_from_buffer(wickr_buffer_t *buffer, uint8_t signature_size)
{
    if (!buffer || buffer->length <= TRANSPORT_PKT_HEADER_SIZE) {
        return NULL;
    }
    
    uint64_t seq_num = ((uint64_t *)buffer->bytes)[0];
    uint8_t type_buffer = buffer->bytes[sizeof(uint64_t)];
    
    wickr_buffer_t *mac_buffer = NULL;
    
    switch (type_buffer) {
        case PAYLOAD_TYPE_HANDSHAKE:
        {
            if (buffer->length <= (TRANSPORT_PKT_HEADER_SIZE + signature_size)) {
                return NULL;
            }
            
            mac_buffer = wickr_buffer_copy_section(buffer, buffer->length - signature_size, signature_size);
            
            if (!mac_buffer) {
                return NULL;
            }
        }
            break;
        case PAYLOAD_TYPE_CIPHERTEXT:
            /* Currently we only support authenticated ciphers for transports, so the mac will be NULL
             since the mac is included in the body as part of the wickr_cipher_result serialization. The
             GCM encryption for example will include the seq_num and type_buffer fields as AAD data so the GCM
             tag in the cipher_result will authenticate the entire packet. Future versions of the library may support
             CTR + HMAC, or something similar, which will create the need for placing the HMAC in the mac field */
            break;
        default:
            return NULL;
    }
    
    uint8_t start_pos = TRANSPORT_PKT_HEADER_SIZE;
    size_t mac_size = mac_buffer == NULL ? 0 : mac_buffer->length;
    
    wickr_buffer_t *body_buffer = wickr_buffer_copy_section(buffer, start_pos,
                                                            buffer->length - mac_size - start_pos);
    
    if (!body_buffer) {
        wickr_buffer_destroy(&mac_buffer);
        return NULL;
    }
    
    wickr_transport_packet_t *pkt = wickr_transport_packet_create(seq_num,
                                                                  (wickr_transport_payload_type)type_buffer,
                                                                  body_buffer,
                                                                  mac_buffer);
    
    if (!pkt) {
        wickr_buffer_destroy(&mac_buffer);
        wickr_buffer_destroy(&body_buffer);
        return NULL;
    }
    
    return pkt;
}

bool wickr_transport_packet_sign(wickr_transport_packet_t *pkt, const wickr_crypto_engine_t *engine, const wickr_identity_t *identity)
{
    if (!pkt || !engine || !identity) {
        return false;
    }
    
    wickr_buffer_t *data_to_sign = wickr_transport_packet_serialize(pkt);
    
    if (!data_to_sign) {
        return false;
    }
    
    wickr_ecdsa_result_t *signature = wickr_identity_sign(identity, engine, data_to_sign);
    wickr_buffer_destroy(&data_to_sign);
    
    if (!signature) {
        return false;
    }
    
    wickr_buffer_t *signature_buffer = wickr_ecdsa_result_serialize(signature);
    wickr_ecdsa_result_destroy(&signature);
    
    if (!signature_buffer) {
        return false;
    }
    
    pkt->mac = signature_buffer;
    
    return true;
}

bool wickr_transport_packet_verify(const wickr_transport_packet_t *packet, const wickr_buffer_t *packet_buffer, const wickr_crypto_engine_t *engine, const wickr_identity_t *identity)
{
    if (!packet || !packet_buffer || !packet->mac) {
        return false;
    }
    
    if (packet_buffer->length <= packet->mac->length) {
        return false;
    }
    
    wickr_ecdsa_result_t *signature = wickr_ecdsa_result_create_from_buffer(packet->mac);
    
    if (!signature) {
        return false;
    }
    
    /* Create a temp buffer with a length that puts it's end before the start of the mac */
    wickr_buffer_t validation_buffer;
    validation_buffer.bytes = packet_buffer->bytes;
    validation_buffer.length = packet_buffer->length - packet->mac->length;
    
    bool return_val = engine->wickr_crypto_engine_ec_verify(signature, identity->sig_key, &validation_buffer);
    
    wickr_ecdsa_result_destroy(&signature);
    
    return return_val;
}


