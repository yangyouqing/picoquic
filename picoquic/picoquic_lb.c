#include "picoquic_internal.h"
#include "picoquic_internal.h"

/*
* Author: Christian Huitema
* Copyright (c) 2021, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "picoquic.h"
#include "picoquic_internal.h"
#include "tls_api.h"
#include "picoquic_lb.h"

/* Load balancer support is defined in https://datatracker.ietf.org/doc/draft-ietf-quic-load-balancers/
 * The draft defines methods for encoding a server ID in a connection identifier, and optionally
 * obfuscating or encrypting the CID value. The CID are generated by the individual servers,
 * based on configuration options provided by the load balancer. The draft also defines
 * methods for generating retry tokens either by a protection box colocated with the
 * load balancer, or at the individual server, with methods for letting individual
 * servers retrieve information from the tokens.
 */

static void picoquic_lb_compat_cid_generate_clear(picoquic_quic_t* quic,
    picoquic_load_balancer_cid_context_t * lb_ctx, picoquic_connection_id_t* cnx_id_returned)
{
    cnx_id_returned->id[0] = lb_ctx->first_byte;
    memcpy(cnx_id_returned->id + 1, lb_ctx->server_id, lb_ctx->server_id_length);
}

static void picoquic_lb_compat_cid_one_pass_stream(void * enc_ctx, uint8_t * nonce, size_t nonce_length, uint8_t * target, size_t target_length)
{
    uint8_t mask[16];
    /* Set the obfuscation value */
    memset(mask, 0, sizeof(mask));
    memcpy(mask, nonce, nonce_length);
    /* Encrypt with ECB */
    picoquic_aes128_ecb_encrypt(enc_ctx, mask, mask, sizeof(mask));
    /* Apply the mask */
    for (size_t i = 0; i < target_length; i++) {
        target[i] ^= mask[i];
    }
}

/* Per specification:
 * Stream Cipher CID {
 *    First Octet (8),
 *    Nonce (64..120),
 *    Encrypted Server ID (8..128-len(Nonce)),
 *    For Server Use (0..152-len(Nonce)-len(Encrypted Server ID)),
 * }
 */

static void picoquic_lb_compat_cid_generate_stream_cipher(picoquic_quic_t* quic,
    picoquic_load_balancer_cid_context_t* lb_ctx, picoquic_connection_id_t* cnx_id_returned)
{
    size_t id_offset = ((size_t)1) + lb_ctx->nonce_length;
    /* Prepare a clear text server ID */
    cnx_id_returned->id[0] = lb_ctx->first_byte;
    memcpy(cnx_id_returned->id + id_offset, lb_ctx->server_id, lb_ctx->server_id_length);
    /* First pass -- obtain intermediate server ID */
    picoquic_lb_compat_cid_one_pass_stream(lb_ctx->cid_encryption_context, cnx_id_returned->id + 1, lb_ctx->nonce_length,
        cnx_id_returned->id + id_offset, lb_ctx->server_id_length);
    /* Second pass -- obtain encrypted nonce */
    picoquic_lb_compat_cid_one_pass_stream(lb_ctx->cid_encryption_context, 
        cnx_id_returned->id + id_offset, lb_ctx->server_id_length,
        cnx_id_returned->id + 1, lb_ctx->nonce_length);
    /* Third pass -- obtain encrypted server-id */
    picoquic_lb_compat_cid_one_pass_stream(lb_ctx->cid_encryption_context, cnx_id_returned->id + 1, lb_ctx->nonce_length,
        cnx_id_returned->id + id_offset, lb_ctx->server_id_length);
}

/* Per specification:
 * Block Cipher CID {
 *    First Octet (8),
 *    Encrypted Server ID (8..128),
 *    Encrypted Bits for Server Use (128-len(Encrypted Server ID)),
 *    Unencrypted Bits for Server Use (0..24),
 * }
 * In theory, the "server use" bits should just be set to a random value.
 * For tests, the server use bits have to be set to a specific value.
 */
static void picoquic_lb_compat_cid_generate_block_cipher(picoquic_quic_t* quic,
    picoquic_load_balancer_cid_context_t* lb_ctx, picoquic_connection_id_t* cnx_id_returned)
{
    cnx_id_returned->id[0] = lb_ctx->first_byte;
    /* Copy the server ID */
    memcpy(cnx_id_returned->id + 1, lb_ctx->server_id, lb_ctx->server_id_length);
    /* encrypt 16 bytes */
    picoquic_aes128_ecb_encrypt(lb_ctx->cid_encryption_context, cnx_id_returned->id + 1, cnx_id_returned->id + 1, 16);
    cnx_id_returned->id[0] = lb_ctx->first_byte;
}

/* This code assumes that the cnx_id_returned value is pre-filled with
 * the expected values of nonces or local-use content.
 */
void picoquic_lb_compat_cid_generate(picoquic_quic_t* quic, picoquic_connection_id_t cnx_id_local,
    picoquic_connection_id_t cnx_id_remote, void* cnx_id_cb_data, picoquic_connection_id_t* cnx_id_returned)
{
    picoquic_load_balancer_cid_context_t* lb_ctx = (picoquic_load_balancer_cid_context_t*)cnx_id_cb_data;
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(cnx_id_local);
    UNREFERENCED_PARAMETER(cnx_id_remote);
#endif
    switch (lb_ctx->method) {
    case picoquic_load_balancer_cid_clear:
        picoquic_lb_compat_cid_generate_clear(quic, lb_ctx, cnx_id_returned);
        break;
    case picoquic_load_balancer_cid_stream_cipher:
        picoquic_lb_compat_cid_generate_stream_cipher(quic, lb_ctx, cnx_id_returned);
        break;
    case picoquic_load_balancer_cid_block_cipher:
        picoquic_lb_compat_cid_generate_block_cipher(quic, lb_ctx, cnx_id_returned);
        break;
    default:
        /* Error, unknown method */
        break;
    }
}

static uint64_t picoquic_lb_compat_cid_verify_clear(picoquic_quic_t* quic,
    picoquic_load_balancer_cid_context_t* lb_ctx, picoquic_connection_id_t const* cnx_id)
{
    uint64_t s_id64 = 0;

    for (size_t i = 0; i < lb_ctx->server_id_length; i++) {
        s_id64 <<= 8;
        s_id64 += cnx_id->id[i + 1];
    }

    return s_id64;
}

static uint64_t picoquic_lb_compat_cid_verify_stream_cipher(picoquic_quic_t* quic,
    picoquic_load_balancer_cid_context_t* lb_ctx, picoquic_connection_id_t const* cnx_id)
{
    size_t id_offset = ((size_t)1) + lb_ctx->nonce_length;
    uint64_t s_id64 = 0;
    picoquic_connection_id_t target = *cnx_id;
    /* First pass -- obtain intermediate server ID */
    picoquic_lb_compat_cid_one_pass_stream(lb_ctx->cid_encryption_context, target.id + 1, lb_ctx->nonce_length,
        target.id + id_offset, lb_ctx->server_id_length);
    /* Second pass -- obtain nonce */
    picoquic_lb_compat_cid_one_pass_stream(lb_ctx->cid_encryption_context,
        target.id + id_offset, lb_ctx->server_id_length, target.id + 1, lb_ctx->nonce_length);
    /* First pass -- obtain server-id */
    picoquic_lb_compat_cid_one_pass_stream(lb_ctx->cid_encryption_context, target.id + 1, lb_ctx->nonce_length,
        target.id + id_offset, lb_ctx->server_id_length);

    /* decode the server ID */
    for (size_t i = 0; i < lb_ctx->server_id_length; i++) {
        s_id64 <<= 8;
        s_id64 += target.id[id_offset + i];
    }

    return s_id64;
}

static uint64_t picoquic_lb_compat_cid_verify_block_cipher(picoquic_quic_t* quic,
    picoquic_load_balancer_cid_context_t* lb_ctx, picoquic_connection_id_t const* cnx_id)
{
    uint8_t decoded[16];
    uint64_t s_id64 = 0;

    /* decrypt 16 bytes */
    picoquic_aes128_ecb_encrypt(lb_ctx->cid_decryption_context, decoded, cnx_id->id + 1, 16);
    /* Decode the server ID */
    if (s_id64 == 0) {
        for (size_t i = 0; i < lb_ctx->server_id_length; i++) {
            s_id64 <<= 8;
            s_id64 += decoded[i];
        }
    }

    return s_id64;
}

uint64_t picoquic_lb_compat_cid_verify(picoquic_quic_t* quic, void* cnx_id_cb_data, picoquic_connection_id_t const* cnx_id)
{
    picoquic_load_balancer_cid_context_t* lb_ctx = (picoquic_load_balancer_cid_context_t*)cnx_id_cb_data;
    uint64_t server_id64;

    if (cnx_id->id_len != lb_ctx->connection_id_length) {
        server_id64 = UINT64_MAX;
    }
    else {
        switch (lb_ctx->method) {
        case picoquic_load_balancer_cid_clear:
            server_id64 = picoquic_lb_compat_cid_verify_clear(quic, lb_ctx, cnx_id);
            break;
        case picoquic_load_balancer_cid_stream_cipher:
            server_id64 = picoquic_lb_compat_cid_verify_stream_cipher(quic, lb_ctx, cnx_id);
            break;
        case picoquic_load_balancer_cid_block_cipher:
            server_id64 = picoquic_lb_compat_cid_verify_block_cipher(quic, lb_ctx, cnx_id);
            break;
        default:
            /* Error, unknown method */
            server_id64 = UINT64_MAX;
            break;
        }
    }

    return server_id64;
}

int picoquic_lb_compat_cid_config(picoquic_quic_t* quic, picoquic_load_balancer_config_t * lb_config)
{
    int ret = 0;

    if (quic->cnx_list != NULL && quic->local_cnxid_length != lb_config->connection_id_length) {
        /* Error. Changing the CID length now will break existing connections */
        ret = -1;
    }
    else if (quic->cnx_id_callback_fn != NULL && quic->cnx_id_callback_ctx != NULL){
        /* Error. Some other CID generation is configured, cannot be changed */
        ret = -1;
    }
    else {
        /* Verify that the method is supported and the parameters are compatible.
         * If valid, configure the connection ID generation */
        if (lb_config->connection_id_length > PICOQUIC_CONNECTION_ID_MAX_SIZE) {
            ret = -1;
        }
        else {
            switch (lb_config->method) {
            case picoquic_load_balancer_cid_clear:
                if (lb_config->server_id_length + 1 > lb_config->connection_id_length) {
                    ret = -1;
                }
                break;
            case picoquic_load_balancer_cid_stream_cipher:
                /* Nonce length must be 8 to 16 bytes, CID should be long enough */
                if (lb_config->nonce_length < 8 || lb_config->nonce_length > 16 ||
                    lb_config->nonce_length + lb_config->server_id_length + 1 > lb_config->connection_id_length) {
                    ret = -1;
                }
                break;
            case picoquic_load_balancer_cid_block_cipher:
                /* CID should include a whole AES-ECB block,
                 * there should be at least 2 bytes available for uniqueness,
                 * zero padding length should be 4 bytes for security */
                if (lb_config->connection_id_length < 17 ||
                    lb_config->server_id_length > 15) {
                    ret = -1;
                }
                break;
            default:
                /* Error, unknown method */
                ret = -1;
                break;
            }
        }
        if (ret == 0) {
            /* Create a copy */
            picoquic_load_balancer_cid_context_t* lb_ctx = (picoquic_load_balancer_cid_context_t*)malloc(sizeof(picoquic_load_balancer_cid_context_t));

            if (lb_ctx == NULL) {
                ret = -1;
            }
            else {
                /* if allocated, create the necessary encryption contexts or variables */
                uint64_t s_id64 = lb_config->server_id64;
                memset(lb_ctx, 0, sizeof(picoquic_load_balancer_cid_context_t));
                lb_ctx->method = lb_config->method;
                lb_ctx->server_id_length = lb_config->server_id_length;
                lb_ctx->nonce_length = lb_config->nonce_length;
                lb_ctx->connection_id_length = lb_config->connection_id_length;
                lb_ctx->first_byte = lb_config->first_byte;
                lb_ctx->server_id64 = lb_config->server_id64;
                lb_ctx->cid_encryption_context = NULL;
                lb_ctx->cid_decryption_context = NULL;
                /* Compute the server ID bytes and set encryption contexts */
                for (size_t i = 0; i < lb_ctx->server_id_length; i++) {
                    size_t j = lb_ctx->server_id_length - i - 1;
                    lb_ctx->server_id[j] = (uint8_t)s_id64;
                    s_id64 >>= 8;
                }
                if (s_id64 != 0) {
                    /* Server ID not long enough to encode actual value */
                    ret = -1;
                } else if (lb_config->method == picoquic_load_balancer_cid_stream_cipher ||
                    lb_config->method == picoquic_load_balancer_cid_block_cipher) {
                    lb_ctx->cid_encryption_context = picoquic_aes128_ecb_create(1, lb_config->cid_encryption_key);
                    if (lb_ctx->cid_encryption_context == NULL) {
                        ret = -1;
                    }
                    else if (lb_config->method == picoquic_load_balancer_cid_block_cipher) {
                        lb_ctx->cid_decryption_context = picoquic_aes128_ecb_create(0, lb_config->cid_encryption_key);
                        if (lb_ctx->cid_decryption_context == NULL) {
                            picoquic_aes128_ecb_free(lb_ctx->cid_encryption_context);
                            lb_ctx->cid_encryption_context = NULL;
                            ret = -1;
                        }
                    }
                }
                if (ret != 0) {
                    /* if context allocation failed, free the copy */
                    free(lb_ctx);
                    lb_ctx = NULL;
                } else {
                    /* Configure the CID generation */
                    quic->local_cnxid_length = lb_ctx->connection_id_length;
                    quic->cnx_id_callback_fn = picoquic_lb_compat_cid_generate;
                    quic->cnx_id_callback_ctx = (void*)lb_ctx;
                }
            }
        }
    }

    return ret;
}

void picoquic_lb_compat_cid_config_free(picoquic_quic_t* quic)
{
    if (quic->cnx_id_callback_fn == picoquic_lb_compat_cid_generate &&
        quic->cnx_id_callback_ctx != NULL) {
        picoquic_load_balancer_cid_context_t* lb_ctx = (picoquic_load_balancer_cid_context_t*)quic->cnx_id_callback_ctx;
        /* Release the encryption contexts so as to avoid memory leaks */
        if (lb_ctx->cid_encryption_context != NULL) {
            picoquic_aes128_ecb_free(lb_ctx->cid_encryption_context);
        }
        if (lb_ctx->cid_decryption_context != NULL) {
            picoquic_aes128_ecb_free(lb_ctx->cid_decryption_context);
        }
        /* Free the data */
        free(lb_ctx);
        /* Reset the Quic context */
        quic->cnx_id_callback_fn = NULL;
        quic->cnx_id_callback_ctx = NULL;
    }
}