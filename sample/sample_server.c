/*
* Author: Christian Huitema
* Copyright (c) 2020, Private Octopus, Inc.
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

/* The "sample" project builds a simple file transfer program that can be
 * instantiated in client or server mode. The "sample_server" implements
 * the server components of the sample application. 
 *
 * Developing the server requires two main components:
 *  - the server "callback" that implements the server side of the
 *    application protocol, managing a server side application context
 *    for each connection.
 *  - the server loop, that reads messages on the socket, submits them
 *    to the Quic context, let the server prepare messages, and send
 *    them on the appropriate socket.
 *
 * The Sample Server uses the "qlog" option to produce Quic Logs as defined
 * in https://datatracker.ietf.org/doc/draft-marx-qlog-event-definitions-quic-h3/.
 * This is an optional feature, which requires linking with the "loglib" library,
 * and using the picoquic_set_qlog() API defined in "autoqlog.h". . When a connection
 * completes, the code saves the log as a file named after the Initial Connection
 * ID (in hexa), with the suffix ".server.qlog".
 */

#include <stdint.h>
#include <stdio.h>
#include <picoquic.h>
#include <picosocks.h>
#include <picoquic_utils.h>
#include <autoqlog.h>
#include "picoquic_sample.h"
#include "picoquic_packet_loop.h"

#include "bp2p_ice_api.h"

static picoquic_quic_t* quic = NULL;

/* Server context and callback management:
 *
 * The server side application context is created for each new connection,
 * and is freed when the connection is closed. It contains a list of
 * server side stream contexts, one for each stream open on the
 * connection. Each stream context includes:
 *  - description of the stream state:
 *      name_read or not, FILE open or not, stream reset or not,
 *      stream finished or not.
 *  - the number of file name bytes already read.
 *  - the name of the file requested by the client.
 *  - the FILE pointer for reading the data.
 * Server side stream context is created when the client starts the
 * stream. It is closed when the file transmission
 * is finished, or when the stream is abandoned.
 *
 * The server side callback is a large switch statement, with one entry
 * for each of the call back events.
 */

typedef struct st_sample_server_stream_ctx_t {
    struct st_sample_server_stream_ctx_t* next_stream;
    struct st_sample_server_stream_ctx_t* previous_stream;
    uint64_t stream_id;
    FILE* F;
    uint8_t file_name[256];
    size_t name_length;
    size_t file_length;
    size_t file_sent;
    unsigned int is_name_read : 1;
    unsigned int is_stream_reset : 1;
    unsigned int is_stream_finished : 1;
} sample_server_stream_ctx_t;

typedef struct st_sample_server_ctx_t {
    char const* default_dir;
    size_t default_dir_len;
    sample_server_stream_ctx_t* first_stream;
    sample_server_stream_ctx_t* last_stream;
} sample_server_ctx_t;

sample_server_stream_ctx_t * sample_server_create_stream_context(sample_server_ctx_t* server_ctx, uint64_t stream_id)
{
    sample_server_stream_ctx_t* stream_ctx = (sample_server_stream_ctx_t*)malloc(sizeof(sample_server_stream_ctx_t));

    if (stream_ctx != NULL) {
        memset(stream_ctx, 0, sizeof(sample_server_stream_ctx_t));

        if (server_ctx->last_stream == NULL) {
            server_ctx->last_stream = stream_ctx;
            server_ctx->first_stream = stream_ctx;
        }
        else {
            stream_ctx->previous_stream = server_ctx->last_stream;
            server_ctx->last_stream->next_stream = stream_ctx;
            server_ctx->last_stream = stream_ctx;
        }
        stream_ctx->stream_id = stream_id;
    }

    return stream_ctx;
}

int sample_server_open_stream(sample_server_ctx_t* server_ctx, sample_server_stream_ctx_t* stream_ctx)
{
    int ret = 0;
    char file_path[1024];

    /* Keep track that the full file name was acquired. */
    stream_ctx->is_name_read = 1;

    /* Verify the name, then try to open the file */
    if (server_ctx->default_dir_len + stream_ctx->name_length + 1 > sizeof(file_path)) {
        ret = PICOQUIC_SAMPLE_NAME_TOO_LONG_ERROR;
    }
    else {
        /* Verify that the default path is empty of terminates with "/" or "\" depending on OS,
         * and format the file path */
        size_t dir_len = server_ctx->default_dir_len;
        if (dir_len > 0) {
            memcpy(file_path, server_ctx->default_dir, dir_len);
            if (file_path[dir_len - 1] != PICOQUIC_FILE_SEPARATOR[0]) {
                file_path[dir_len] = PICOQUIC_FILE_SEPARATOR[0];
                dir_len++;
            }
        }
        memcpy(file_path + dir_len, stream_ctx->file_name, stream_ctx->name_length);
        file_path[dir_len + stream_ctx->name_length] = 0;

        /* Use the picoquic_file_open API for portability to Windows and Linux */
        stream_ctx->F = picoquic_file_open(file_path, "rb");

        if (stream_ctx->F == NULL) {
            ret = PICOQUIC_SAMPLE_NO_SUCH_FILE_ERROR;
        }
        else {
            /* Assess the file size, as this is useful for data planning */
            long sz;
            fseek(stream_ctx->F, 0, SEEK_END);
            sz = ftell(stream_ctx->F);

            if (sz <= 0) {
                stream_ctx->F = picoquic_file_close(stream_ctx->F);
                ret = PICOQUIC_SAMPLE_FILE_READ_ERROR;
            }
            else {
                stream_ctx->file_length = (size_t)sz;
                fseek(stream_ctx->F, 0, SEEK_SET);
                ret = 0;
            }
        }
    }

    return ret;
}

void sample_server_delete_stream_context(sample_server_ctx_t* server_ctx, sample_server_stream_ctx_t* stream_ctx)
{
    /* Close the file if it was open */
    if (stream_ctx->F != NULL) {
        stream_ctx->F = picoquic_file_close(stream_ctx->F);
    }

    /* Remove the context from the server's list */
    if (stream_ctx->previous_stream == NULL) {
        server_ctx->first_stream = stream_ctx->next_stream;
    }
    else {
        stream_ctx->previous_stream->next_stream = stream_ctx->next_stream;
    }

    if (stream_ctx->next_stream == NULL) {
        server_ctx->last_stream = stream_ctx->previous_stream;
    }
    else {
        stream_ctx->next_stream->previous_stream = stream_ctx->previous_stream;
    }

    /* release the memory */
    free(stream_ctx);
}

void sample_server_delete_context(sample_server_ctx_t* server_ctx)
{
    /* Delete any remaining stream context */
    while (server_ctx->first_stream != NULL) {
        sample_server_delete_stream_context(server_ctx, server_ctx->first_stream);
    }

    /* release the memory */
    free(server_ctx);
}

int sample_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    sample_server_ctx_t* server_ctx = (sample_server_ctx_t*)callback_ctx;
    sample_server_stream_ctx_t* stream_ctx = (sample_server_stream_ctx_t*)v_stream_ctx;

    /* If this is the first reference to the connection, the application context is set
     * to the default value defined for the server. This default value contains the pointer
     * to the file directory in which all files are defined.
     */
    if (callback_ctx == NULL || callback_ctx == picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx))) {
        server_ctx = (sample_server_ctx_t *)malloc(sizeof(sample_server_ctx_t));
        if (server_ctx == NULL) {
            /* cannot handle the connection */
            picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
            return -1;
        }
        else {
            sample_server_ctx_t* d_ctx = (sample_server_ctx_t*)picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx));
            if (d_ctx != NULL) {
                memcpy(server_ctx, d_ctx, sizeof(sample_server_ctx_t));
            }
            else {
                /* This really is an error case: the default connection context should never be NULL */
                memset(server_ctx, 0, sizeof(sample_server_ctx_t));
                server_ctx->default_dir = "";
            }
            picoquic_set_callback(cnx, sample_server_callback, server_ctx);
        }
    }

    if (ret == 0) {
        switch (fin_or_event) {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            /* Data arrival on stream #x, maybe with fin mark */
            if (stream_ctx == NULL) {
                /* Create and initialize stream context */
                stream_ctx = sample_server_create_stream_context(server_ctx, stream_id);
            }

            if (stream_ctx == NULL) {
                /* Internal error */
                (void) picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_INTERNAL_ERROR);
                return(-1);
            }
            else if (stream_ctx->is_name_read) {
                /* Write after fin? */
                return(-1);
            }
            else {
                /* Accumulate data */
                size_t available = sizeof(stream_ctx->file_name) - stream_ctx->name_length - 1;

                if (length > available) {
                    /* Name too long: reset stream! */
                    sample_server_delete_stream_context(server_ctx, stream_ctx);
                    (void) picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_NAME_TOO_LONG_ERROR);
                }
                else {
                    if (length > 0) {
                        memcpy(stream_ctx->file_name + stream_ctx->name_length, bytes, length);
                        stream_ctx->name_length += length;
                    }
                    if (fin_or_event == picoquic_callback_stream_fin) {
                        int stream_ret;

                        /* If fin, mark read, check the file, open it. Or reset if there is no such file */
                        stream_ctx->file_name[stream_ctx->name_length + 1] = 0;
                        stream_ctx->is_name_read = 1;
                        stream_ret = sample_server_open_stream(server_ctx, stream_ctx);

                        if (stream_ret == 0) {
                            /* If data needs to be sent, set the context as active */
                            ret = picoquic_mark_active_stream(cnx, stream_id, 1, stream_ctx);
                        }
                        else {
                            /* If the file could not be read, reset the stream */
                            sample_server_delete_stream_context(server_ctx, stream_ctx);
                            (void) picoquic_reset_stream(cnx, stream_id, stream_ret);
                        }
                    }
                }
            }
            break;
        case picoquic_callback_prepare_to_send:
            /* Active sending API */
            if (stream_ctx == NULL) {
                /* This should never happen */
            }
            else if (stream_ctx->F == NULL) {
                /* Error, asking for data after end of file */
            }
            else {
                /* Implement the zero copy callback */
                size_t available = stream_ctx->file_length - stream_ctx->file_sent;
                int is_fin = 1;
                uint8_t* buffer;

                if (available > length) {
                    available = length;
                    is_fin = 0;
                }
                
                buffer = picoquic_provide_stream_data_buffer(bytes, available, is_fin, !is_fin);
                if (buffer != NULL) {
                    size_t nb_read = fread(buffer, 1, available, stream_ctx->F);

                    if (nb_read != available) {
                        /* Error while reading the file */
                        sample_server_delete_stream_context(server_ctx, stream_ctx);
                        (void)picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_FILE_READ_ERROR);
                    }
                    else {
                        stream_ctx->file_sent += available;
                    }
                }
                else {
                /* Should never happen according to callback spec. */
                    ret = -1;
                }
            }
            break;
        case picoquic_callback_stream_reset: /* Client reset stream #x */
        case picoquic_callback_stop_sending: /* Client asks server to reset stream #x */
            if (stream_ctx != NULL) {
                /* Mark stream as abandoned, close the file, etc. */
                sample_server_delete_stream_context(server_ctx, stream_ctx);
                picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_FILE_CANCEL_ERROR);
            }
            break;
        case picoquic_callback_stateless_reset: /* Received an error message */
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            /* Delete the server application context */
            sample_server_delete_context(server_ctx);
            picoquic_set_callback(cnx, NULL, NULL);
            break;
        case picoquic_callback_version_negotiation:
            /* The server should never receive a version negotiation response */
            break;
        case picoquic_callback_stream_gap:
            /* This callback is never used. */
            break;
        case picoquic_callback_almost_ready:
        case picoquic_callback_ready:
            /* Check that the transport parameters are what the sample expects */
            break;
        default:
            /* unexpected */
            break;
        }
    }

    return ret;
}



static void do_send(struct ev_loop *loop, struct ev_timer *w, int revents)
{
    static uint64_t last_time = 0;
    
    uint64_t current_time = picoquic_get_quic_time(quic);
    uint64_t diff = current_time - last_time;
    if (diff > 20*1000) {
        printf ("diff-dosend: %llu\n", diff);
    }
    last_time = current_time;

    
    uint8_t buffer[1536];
    uint8_t send_buffer[1536] = {0};
    
    size_t send_buffer_size = 1536;
    size_t send_length = 0;
    picoquic_connection_id_t log_cid;
    picoquic_cnx_t* last_cnx = NULL;
    size_t* send_msg_ptr = NULL;
    size_t send_msg_size = 0;
    
    int testing_migration = 0; /* Hook for the migration test */

    int ret = 0;
    while (ret == 0) {
        struct sockaddr_storage peer_addr;
        struct sockaddr_storage local_addr;
        int if_index = 0;
        int sock_ret = 0;
        int sock_err = 0;

        ret = picoquic_prepare_next_packet_ex(quic, current_time,
            send_buffer, send_buffer_size, &send_length,
            &peer_addr, &local_addr, &if_index, &log_cid, &last_cnx,
            send_msg_ptr);

        if (ret == 0 && send_length > 0) {
            
            sock_ret = picoquic_sendmsg2(quic,
                    (const char*)send_buffer, (int)send_length);

            if (sock_ret <= 0) {
                if (last_cnx == NULL) {
                    picoquic_log_context_free_app_message(quic, &log_cid, "Could not send message to AF_to=%d, AF_from=%d, if=%d, ret=%d, err=%d",
                        peer_addr.ss_family, local_addr.ss_family, if_index, sock_ret, sock_err);
                }
                else {
                    picoquic_log_app_message(last_cnx, "Could not send message to AF_to=%d, AF_from=%d, if=%d, ret=%d, err=%d",
                        peer_addr.ss_family, local_addr.ss_family, if_index, sock_ret, sock_err);
                    
                    if (picoquic_socket_error_implies_unreachable(sock_err)) {
                        picoquic_notify_destination_unreachable(last_cnx, current_time,
                            (struct sockaddr*) & peer_addr, (struct sockaddr*) & local_addr, if_index,
                            sock_err);
                    } else if (sock_err == EIO) {
                        size_t packet_index = 0;
                        size_t packet_size = send_msg_size;

                        while (packet_index < send_length) {
                            if (packet_index + packet_size > send_length) {
                                packet_size = send_length - packet_index;
                            }
                            sock_ret = picoquic_sendmsg2(quic,
                                (const char*)(send_buffer + packet_index), (int)packet_size);
                            if (sock_ret > 0) {
                                packet_index += packet_size;
                            }
                            else {
                                picoquic_log_app_message(last_cnx, "Retry with packet size=%zu fails at index %zu, ret=%d, err=%d.",
                                    packet_size, packet_index, sock_ret, sock_err);
                                break;
                            }
                        }
                        if (sock_ret > 0) {
                            picoquic_log_app_message(last_cnx, "Retry of %zu bytes by chunks of %zu bytes succeeds.",
                                send_length, send_msg_size);
                        }
                    }
                }
            } else {
            }
        }
        else {
            break;
        }
    }
    
}


static void on_recv_pkt(void* pkt, int size, struct sockaddr* src, struct sockaddr* dest) 
{
    uint16_t src_port = -1;
    char *src_addr = NULL;
    struct sockaddr_in *sin = (struct sockaddr_in *)src;
    src_port = ntohs(sin->sin_port); 
    src_addr = inet_ntoa(sin->sin_addr);
    static uint64_t last_time = 0;
    uint64_t current_time = picoquic_get_quic_time(quic);

    printf ("diff-recv: %llu, recv %d bytes from[%s:%d]\n", current_time - last_time, size, src_addr, src_port);
    last_time = current_time;

//    int if_index_to = 2;
      int if_index_to = 0;


    (void)picoquic_incoming_packet(quic, pkt,
        (size_t)size, (struct sockaddr*)src,
        (struct sockaddr*)dest, if_index_to, 0,
        current_time);

    do_send(NULL, NULL, 0);
    //if (loop_callback != NULL) {
    //    ret = loop_callback(quic, picoquic_packet_loop_after_receive, loop_callback_ctx);
    //}           
}

static void ice_on_idle()
{
    do_send(NULL, NULL, 0);    
}


static void ice_on_status_change(ice_status_t s)
{
    static ice_status_t from = ICE_STATUS_INIT;
    printf ("ICE status changed[%d->%d]", from, s);
    from = s;
//    if (ICE_STATUS_COMPLETE == s) {
//        bp2p_ice_stop(&ice_cfg);
//    }
}



static int on_picoquic_send_pkt(picoquic_quic_t* quic, const char* bytes, int length)
{
    int byte_sent = -1;
    byte_sent = bp2p_ice_send(bytes, length);
    static uint64_t last_time = 0;
    uint64_t current_time = picoquic_get_quic_time(quic);    
    
    printf ("diff-sent: %llu, sent %d bytes\n", current_time - last_time, length);
    last_time = current_time;
    
    return byte_sent;
}




/* Server loop setup:
 * - Create the QUIC context.
 * - Open the sockets
 * - On a forever loop:
 *     - get the next wakeup time
 *     - wait for arrival of message on sockets until that time
 *     - if a message arrives, process it.
 *     - else, check whether there is something to send.
 *       if there is, send it.
 * - The loop breaks if the socket return an error. 
 */

int picoquic_sample_server(const char* server_cert, const char* server_key, const char* default_dir)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    char const* qlog_dir = PICOQUIC_SAMPLE_SERVER_QLOG_DIR;
    uint64_t current_time = 0;
    sample_server_ctx_t default_context = { 0 };

    default_context.default_dir = default_dir;
    default_context.default_dir_len = strlen(default_dir);


    /* Create the QUIC context for the server */
    current_time = picoquic_current_time();
    /* Create QUIC context */
    quic = picoquic_create(8, server_cert, server_key, NULL, PICOQUIC_SAMPLE_ALPN,
        sample_server_callback, &default_context, NULL, NULL, NULL, current_time, NULL, NULL, NULL, 0);

    if (quic == NULL) {
        fprintf(stderr, "Could not create server context\n");
        ret = -1;
    }
    else {
        picoquic_set_cookie_mode(quic, 2);

        picoquic_set_default_congestion_algorithm(quic, picoquic_bbr_algorithm);

        picoquic_set_qlog(quic, qlog_dir);

        picoquic_set_log_level(quic, 1);

        picoquic_set_key_log_file_from_env(quic);

        picoquic_set_send_data_fn(quic, on_picoquic_send_pkt);
    }

    /* Wait for packets */
//    if (ret == 0) {
//        ret = picoquic_packet_loop(quic, server_port, 0, 0, 0, 0, NULL, NULL);
//    }
    ice_cfg_t ice_cfg;
    ice_cfg.loop = EV_DEFAULT;
    ice_cfg.role = ICE_ROLE_PEER;
    strcpy (ice_cfg.my_channel, "sample-server");

    
    ice_cfg.signalling_srv = "43.128.22.4";
    ice_cfg.stun_srv = "43.128.22.4";
    ice_cfg.turn_srv = "43.128.22.4";
    ice_cfg.turn_username = "yyq";
    ice_cfg.turn_password = "yyq";
    ice_cfg.turn_fingerprint = 1;
    ice_cfg.cb_on_rx_pkt = on_recv_pkt;
    ice_cfg.cb_on_status_change = ice_on_status_change;
    ice_cfg.cb_on_idle_running = ice_on_idle;


    bp2p_ice_init (&ice_cfg);
    ev_run(ice_cfg.loop, 0);

    /* And finish. */
    printf("Server exit, ret = %d\n", ret);

    /* Clean up */
    if (quic != NULL) {
        picoquic_free(quic);
    }

    return ret;
}

int main(int argc, char** argv) {
    int exit_code = 0;
    char *server_cert = "certs/cert.pem";
    char *server_key = "certs/key.pem";
    char *dir = "server_dir";
    
    
    exit_code = picoquic_sample_server(server_cert, server_key, dir);
    exit(exit_code);
    
    return 1;
}

