/*
 * Copyright © 2012-2017 Wickr Inc.  All rights reserved.
 *
 * This code is being released for EDUCATIONAL, ACADEMIC, AND CODE REVIEW PURPOSES
 * ONLY.  COMMERCIAL USE OF THE CODE IS EXPRESSLY PROHIBITED.  For additional details,
 * please see LICENSE
 *
 * THE CODE IS MADE AVAILABLE "AS-IS" AND WITHOUT ANY EXPRESS OR
 * IMPLIED GUARANTEES AS TO FITNESS, MERCHANTABILITY, NON-
 * INFRINGEMENT OR OTHERWISE. IT IS NOT BEING PROVIDED IN TRADE BUT ON
 * A VOLUNTARY BASIS ON BEHALF OF THE AUTHOR’S PART FOR THE BENEFIT
 * OF THE LICENSEE AND IS NOT MADE AVAILABLE FOR CONSUMER USE OR ANY
 * OTHER USE OUTSIDE THE TERMS OF THIS LICENSE. ANYONE ACCESSING THE
 * CODE SHOULD HAVE THE REQUISITE EXPERTISE TO SECURE THEIR SYSTEM
 * AND DEVICES AND TO ACCESS AND USE THE CODE FOR REVIEW PURPOSES
 * ONLY. LICENSEE BEARS THE RISK OF ACCESSING AND USING THE CODE. IN
 * PARTICULAR, AUTHOR BEARS NO LIABILITY FOR ANY INTERFERENCE WITH OR
 * ADVERSE EFFECT THAT MAY OCCUR AS A RESULT OF THE LICENSEE
 * ACCESSING AND/OR USING THE CODE ON LICENSEE’S SYSTEM.
 */

#ifndef transport_priv_h
#define transport_priv_h

#include "transport_ctx.h"
#include "stream_cipher.h"

typedef enum { PAYLOAD_TYPE_HANDSHAKE, PAYLOAD_TYPE_CIPHERTEXT } wickr_transport_payload_type;

struct wickr_transport_ctx {
    wickr_crypto_engine_t engine;
    wickr_node_t *local_identity;
    wickr_node_t *remote_identity;
    wickr_stream_ctx_t *rx_stream;
    wickr_stream_ctx_t *tx_stream;
    wickr_transport_status status;
    uint32_t evo_count;
    wickr_transport_callbacks_t callbacks;
};

#define CURRENT_HANDSHAKE_VERSION 1
#define TRANSPORT_PKT_HEADER_SIZE (sizeof(uint64_t) + sizeof(uint8_t))


typedef enum { WICKR_HANDSHAKE_PHASE_INIT, WICKR_HANDSHAKE_PHASE_RESPONSE, WICKR_HANDSHAKE_PHASE_FINALIZE } wickr_handshake_phase;

struct wickr_transport_packet {
    uint64_t seq_num;
    wickr_transport_payload_type body_type;
    wickr_buffer_t *body;
    wickr_buffer_t *mac;
};

typedef struct wickr_transport_packet wickr_transport_packet_t;

wickr_transport_packet_t *wickr_transport_packet_create(uint64_t seq_num, wickr_transport_payload_type body_type, wickr_buffer_t *body, wickr_buffer_t *mac);
wickr_transport_packet_t *wickr_transport_packet_copy(wickr_transport_packet_t *pkt);
void wickr_transport_packet_destroy(wickr_transport_packet_t **pkt);

wickr_buffer_t *wickr_transport_packet_serialize(wickr_transport_packet_t *pkt);
wickr_transport_packet_t *wickr_transport_packet_create_from_buffer(wickr_buffer_t *buffer, uint8_t signature_size);
wickr_buffer_t *wickr_transport_packet_make_meta_buffer(wickr_transport_packet_t *pkt);


#endif /* transport_priv_h */
