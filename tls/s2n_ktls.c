/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/tls.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bits/stdint-uintn.h"
#include "utils/s2n_result.h"
#define SOL_TCP 6
#define TCP_ULP 31 /* Attach a ULP to a TCP connection.  */
#define SOL_TLS 282
#define TLS_TX 1 /* Set transmit parameters */
#define TLS_RX 2 /* Set receive parameters */
#define _TLS_VERSION_NUMBER(id) ((((0x3) & 0xFF) << 8) | ((0x4) & 0xFF))
#define _TLS_1_3_VERSION _TLS_VERSION_NUMBER(TLS_1_3)
#define TLS_GET_RECORD_TYPE 2

#include "api/s2n.h"
#include "tls/s2n_alerts.h"
#include "tls/s2n_ktls.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_safety_macros.h"
#include "utils/s2n_socket.h"

S2N_RESULT s2n_ktls_rx_keys(struct s2n_connection *conn, int fd, uint8_t implicit_iv[ S2N_TLS_MAX_IV_LEN ],
                            uint8_t sequence_number[ S2N_TLS_SEQUENCE_NUM_LEN ], uint8_t key[ 16 ])
{
    struct tls12_crypto_info_aes_gcm_128 crypto_info;

    crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
    RESULT_CHECKED_MEMCPY(crypto_info.salt, implicit_iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
    RESULT_CHECKED_MEMCPY(crypto_info.rec_seq, sequence_number, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
    RESULT_CHECKED_MEMCPY(crypto_info.key, key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);

    /* for TLS 1.2 IV is generated in kernel */
    if (conn->actual_protocol_version == S2N_TLS12) {
        crypto_info.info.version = TLS_1_2_VERSION;
        RESULT_CHECKED_MEMCPY(crypto_info.iv, implicit_iv, TLS_CIPHER_AES_GCM_128_IV_SIZE);
    } else if (conn->actual_protocol_version == S2N_TLS13) {
        crypto_info.info.version = _TLS_1_3_VERSION;
        RESULT_CHECKED_MEMCPY(crypto_info.iv, implicit_iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE,
                              TLS_CIPHER_AES_GCM_128_IV_SIZE);
    } else {
        fprintf(stderr, "ktls only supported for tls1.2 and tls1.3 xxxxxxxxxxxxxx: %d\n",
                conn->actual_protocol_version);
    }

    /* set keys */
    int ret_val = setsockopt(fd, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info));
    if (ret_val < 0) {
        fprintf(stderr, "ktls set RX key xxxxxxxxxxxxxx: %s\n", strerror(errno));
        return S2N_RESULT_ERROR;
    } else {
        fprintf(stderr, "ktls RX keys set---------- \n");
    }

    return S2N_RESULT_OK;
}

int s2n_ktls_read_fn(void *io_context, uint8_t *buf, uint32_t len)
{
    POSIX_ENSURE_REF(io_context);
    POSIX_ENSURE_REF(buf);
    int rfd = (( struct s2n_ktls_read_io_context * )io_context)->fd;
    if (rfd < 0) {
        errno = EBADF;
        POSIX_BAIL(S2N_ERR_BAD_FD);
    }

    /* On success, the number of bytes read is returned. On failure, -1 is
     * returned and errno is set appropriately. */
    fprintf(stdout, "ktls reading---------- len: %d\n", len);
    ssize_t result = read(rfd, buf, len);
    fprintf(stdout, "ktls reading done---------- result: %zd\n", result);
    POSIX_ENSURE_INCLUSIVE_RANGE(INT_MIN, result, INT_MAX);
    return result;
}

int s2n_connection_set_ktls_read_fd(struct s2n_connection *conn, int rfd)
{
    struct s2n_blob                  ctx_mem = { 0 };
    struct s2n_ktls_read_io_context *peer_ktls_ctx;

    POSIX_ENSURE_REF(conn);
    POSIX_GUARD(s2n_alloc(&ctx_mem, sizeof(struct s2n_ktls_read_io_context)));
    POSIX_GUARD(s2n_blob_zero(&ctx_mem));

    peer_ktls_ctx                  = ( struct s2n_ktls_read_io_context                  *)( void                  *)ctx_mem.data;
    peer_ktls_ctx->fd              = rfd;
    peer_ktls_ctx->ktls_socket_set = true;

    POSIX_GUARD(s2n_connection_set_recv_cb(conn, s2n_ktls_read_fn));
    POSIX_GUARD(s2n_connection_set_recv_ctx(conn, peer_ktls_ctx));
    conn->managed_recv_io = true;

    /* This is only needed if the user is using corked io.
     * Take the snapshot in case optimized io is enabled after setting the fd.
     */
    POSIX_GUARD(s2n_socket_read_snapshot(conn));

    return 0;
}

S2N_RESULT s2n_klts_recv_ctrl_msg(int sock, uint8_t *record_type, void *data, size_t length)
{
    char   *buf = data;
    ssize_t ret;

    char            cmsg[ CMSG_SPACE(sizeof(unsigned char)) ];
    struct msghdr   msg = { 0 };
    struct iovec    msg_iov;
    struct cmsghdr *hdr;

    /* receive message */
    msg.msg_control    = cmsg;
    msg.msg_controllen = sizeof cmsg;

    msg_iov.iov_base = buf;
    msg_iov.iov_len  = length;

    msg.msg_iov    = &msg_iov;
    msg.msg_iovlen = 1;

    ret = recvmsg(sock, &msg, MSG_DONTWAIT);

    if (ret == -1) {
        fprintf(stderr, "-------------ktls recv cmsg xxxxxxxxxxxxxx: errno %s\n", strerror(errno));
        return S2N_RESULT_ERROR;
    }

    /* connection closed */
    if (ret == 0) {
        return S2N_RESULT_ERROR;
    } else {
        fprintf(stderr, "ktls recv cmsg ---------- : type: %s\n", record_type);
    }

    /* get record type from header */
    hdr = CMSG_FIRSTHDR(&msg);
    if (hdr == NULL) { return S2N_RESULT_ERROR; }
    if (hdr->cmsg_level == SOL_TLS && hdr->cmsg_type == TLS_GET_RECORD_TYPE) {
        *record_type = *( unsigned char * )CMSG_DATA(hdr);
    } else {
        *record_type = TLS_APPLICATION_DATA;
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_klts_send_ctrl_msg(int sock, uint8_t record_type, void *data, size_t length)
{
    const char *buf = data;
    /* ssize_t ret; */
    /* int sockin, sockout; */
    size_t data_to_send = length;

    char            cmsg[ CMSG_SPACE(sizeof(unsigned char)) ];
    struct msghdr   msg = { 0 };
    struct iovec    msg_iov; /* Vector of data to send/receive into. */
    struct cmsghdr *hdr;

    msg.msg_control    = cmsg;
    msg.msg_controllen = sizeof cmsg;

    hdr             = CMSG_FIRSTHDR(&msg);
    hdr->cmsg_level = SOL_TLS;
    hdr->cmsg_type  = TLS_SET_RECORD_TYPE;
    hdr->cmsg_len   = CMSG_LEN(sizeof(unsigned char));

    // construct record header
    *CMSG_DATA(hdr)    = record_type;
    msg.msg_controllen = hdr->cmsg_len;

    msg_iov.iov_base = ( void * )buf;
    msg_iov.iov_len  = data_to_send;

    msg.msg_iov    = &msg_iov;
    msg.msg_iovlen = 1;

    int ret_val = sendmsg(sock, &msg, 0);
    if (ret_val < 0) {
        fprintf(stderr, "-------------ktls send cmsg xxxxxxxxxxxxxx: type: %d, errno %s\n", record_type,
                strerror(errno));
        return S2N_RESULT_ERROR;
    } else {
        fprintf(stderr, "ktls send cmsg ---------- : type: %d\n", record_type);
    }

    return S2N_RESULT_OK;
}

int s2n_ktls_write_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    POSIX_ENSURE_REF(io_context);
    POSIX_ENSURE_REF(buf);
    int wfd = (( struct s2n_ktls_write_io_context * )io_context)->fd;
    if (wfd < 0) {
        errno = EBADF;
        POSIX_BAIL(S2N_ERR_BAD_FD);
    }

    /* On success, the number of bytes written is returned. On failure, -1 is
     * returned and errno is set appropriately. */

    /* fprintf(stdout, "ktls writing---------- len: %d\n", len); */
    ssize_t result = write(wfd, buf, len);
    /* fprintf(stdout, "ktls writing done---------- result: %zd\n", result); */
    POSIX_ENSURE_INCLUSIVE_RANGE(INT_MIN, result, INT_MAX);
    return result;
}

int s2n_connection_set_ktls_write_fd(struct s2n_connection *conn, int wfd)
{
    struct s2n_blob                   ctx_mem = { 0 };
    struct s2n_ktls_write_io_context *peer_ktls_ctx;

    POSIX_ENSURE_REF(conn);
    POSIX_GUARD(s2n_alloc(&ctx_mem, sizeof(struct s2n_ktls_write_io_context)));

    peer_ktls_ctx                  = ( struct s2n_ktls_write_io_context                  *)( void                  *)ctx_mem.data;
    peer_ktls_ctx->fd              = wfd;
    peer_ktls_ctx->ktls_socket_set = true;

    POSIX_GUARD(s2n_connection_set_send_cb(conn, s2n_ktls_write_fn));
    POSIX_GUARD(s2n_connection_set_send_ctx(conn, peer_ktls_ctx));
    conn->managed_send_io = true;

    /* This is only needed if the user is using corked io.
     * Take the snapshot in case optimized io is enabled after setting the fd.
     */
    POSIX_GUARD(s2n_socket_write_snapshot(conn));

    uint8_t ipv6;
    if (0 == s2n_socket_is_ipv6(wfd, &ipv6)) { conn->ipv6 = (ipv6 ? 1 : 0); }

    conn->write_fd_broken = 0;

    return 0;
}

S2N_RESULT s2n_ktls_tx_keys(struct s2n_connection *conn, int fd, uint8_t implicit_iv[ S2N_TLS_MAX_IV_LEN ],
                            uint8_t sequence_number[ S2N_TLS_SEQUENCE_NUM_LEN ], uint8_t key[ 16 ])
{
    struct tls12_crypto_info_aes_gcm_128 crypto_info;

    crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
    RESULT_CHECKED_MEMCPY(crypto_info.salt, implicit_iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
    RESULT_CHECKED_MEMCPY(crypto_info.rec_seq, sequence_number, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
    RESULT_CHECKED_MEMCPY(crypto_info.key, key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);

    if (conn->actual_protocol_version == S2N_TLS12) {
        crypto_info.info.version = TLS_1_2_VERSION;
        RESULT_CHECKED_MEMCPY(crypto_info.iv, implicit_iv, TLS_CIPHER_AES_GCM_128_IV_SIZE);
    } else if (conn->actual_protocol_version == S2N_TLS13) {
        crypto_info.info.version = _TLS_1_3_VERSION;
        RESULT_CHECKED_MEMCPY(crypto_info.iv, implicit_iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE,
                              TLS_CIPHER_AES_GCM_128_IV_SIZE);
    } else {
        fprintf(stderr, "ktls only supported for tls1.2 and tls1.3 xxxxxxxxxxxxxx: %d\n",
                conn->actual_protocol_version);
    }

    /* set keys */
    int ret_val = setsockopt(fd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info));
    if (ret_val < 0) {
        fprintf(stderr, "ktls set TX key xxxxxxxxxxxxxx: %s\n", strerror(errno));
        return S2N_RESULT_ERROR;
    } else {
        fprintf(stderr, "ktls TX keys set---------- \n");
    }

    return S2N_RESULT_OK;
}

/* only enable server send and client receive kTLS */
S2N_RESULT s2n_ktls_set_keys(struct s2n_connection *conn, int fd)
{
    RESULT_ENSURE_REF(conn);

    RESULT_ENSURE_EQ(sizeof(conn->client_key), TLS_CIPHER_AES_GCM_128_KEY_SIZE);
    RESULT_ENSURE_EQ(sizeof(conn->server_key), TLS_CIPHER_AES_GCM_128_KEY_SIZE);
    if (conn->mode == S2N_SERVER) {
        RESULT_GUARD(s2n_ktls_tx_keys(conn, fd, conn->server->server_implicit_iv, conn->server->server_sequence_number,
                                      conn->server_key));
        /* RESULT_GUARD(s2n_ktls_rx_keys(conn, fd, conn->client->client_implicit_iv, conn->client->client_sequence_number, */
        /*                               conn->client_key)); */

        conn->ktls_enabled_send_io = true;
        RESULT_GUARD_POSIX(s2n_connection_set_ktls_write_fd(conn, fd));
    } else {
        /* RESULT_GUARD(s2n_ktls_tx_keys(conn, fd, conn->client->client_implicit_iv, conn->client->client_sequence_number, */
        /*                               conn->client_key)); */
        RESULT_GUARD(s2n_ktls_rx_keys(conn, fd, conn->server->server_implicit_iv, conn->server->server_sequence_number,
                                      conn->server_key));

        conn->ktls_enabled_recv_io = true;
        RESULT_GUARD_POSIX(s2n_connection_set_ktls_read_fd(conn, fd));
    }

    return S2N_RESULT_OK;

    /* char filename[] = "sample.txt"; */
    /* int send_times = 1000000; // 2gb */

    /* char filename[] = "sample.txt.500b"; */
    /* int send_times = 4000000; // 2gb */
    /* char filename[] = "sample.txt.1k"; */
    /* int send_times = 2000000; // 2gb */
    /* char filename[] = "sample.txt.2k"; */
    /* int send_times = 1000000; // 2gb */
    /* char filename[] = "sample.txt.4k"; */
    /* int  send_times = 500000;  // 2gb */
    /* char filename[] = "sample.txt.8k"; */
    /* int send_times = 250000; // 2gb */
    /* char filename[] = "sample.txt.16k"; */
    /* int send_times = 125000; // 2gb */
    /* char filename[] = "sample.txt.33k"; */
    /* int send_times = 60600; // 2gb */
    /* char filename[] = "sample.txt.67k"; */
    /* int send_times = 30300; // 2gb */
    /* char filename[] = "sample.txt.133k"; */
    /* int send_times = 15000; // 2gb */
    /* char filename[] = "sample.txt.266k"; */
    /* int send_times = 7500; // 2gb */
    /* char filename[] = "sample.txt.400k"; */
    /* int send_times = 5000; // 2gb */
    /* char filename[] = "sample.txt.4m"; */
    /* int send_times = 500; // 2gb */
    /* fprintf(stderr, "starting sendfile -------------- file: %s times: %d \n", filename, send_times); */

    /* if (conn->mode == S2N_CLIENT) { */
    /*     for (int i = 0; i <= send_times; i++) { */
    /*         int         fd1; */
    /*         struct stat stbuf; */
    /*         /1* open *1/ */
    /*         if ((fd1 = open(filename, O_RDWR)) < 0) { */
    /*             fprintf(stderr, "error open file sample.txt xxxxxxxxxxxxxx  %s\n", strerror(errno)); */
    /*         } */

    /*         fstat(fd1, &stbuf); */
    /*         /1* fprintf(stderr, "file of size sent -------------- %ld\n", stbuf.st_size); *1/ */
    /*         int rv; */
    /*         /1* sendfile *1/ */
    /*         if ((rv = sendfile(fd, fd1, 0, stbuf.st_size)) < 0) { */
    /*             fprintf(stderr, "error sendfile xxxxxxxxxxxxxx  %d %s\n", rv, strerror(errno)); */
    /*         } */
    /*     } */
    /* } */
    /* fprintf(stderr, "file sent -------------- \n"); */

    /* send plaintext since we are using ktls */
    /* { */
    /*     const char *msg = "hello world\n"; */
    /*     int ret_val = write(fd, msg, strlen(msg)); */
    /*     if (ret_val < 0) { */
    /*         fprintf(stderr, "ktls write failed 5 xxxxxxxxxxxxxx: %s\n", strerror(errno)); */
    /*         return S2N_RESULT_ERROR; */
    /*     } else { */
    /*         fprintf(stdout, "ktls wrote hello world success---------- \n"); */
    /*     } */
    /* } */

    /* send alert via ktls */
    /* { */
    /* int     s2n_tls_alert_level_fatal = 2; */
    /* uint8_t alert[ 2 ]; */
    /* alert[ 0 ] = s2n_tls_alert_level_fatal; */
    /* alert[ 1 ] = S2N_TLS_ALERT_CLOSE_NOTIFY; */
    /* RESULT_GUARD(s2n_klts_send_ctrl_msg(fd, TLS_ALERT, alert, S2N_ALERT_LENGTH)); */
    /* } */
}

/* sendfile */
int s2n_connection_sendfile(struct s2n_connection *conn, int file_fd, size_t size)
{
    POSIX_ENSURE_REF(conn);

    int rv;
    /* sendfile */
    if ((rv = sendfile(conn->sendfd, file_fd, 0, size)) < 0) {
        /* fprintf(stderr, "error sendfile xxxxxxxxxxxxxx  %d %s\n", rv, strerror(errno)); */
        POSIX_BAIL(S2N_ERR_BAD_FD);
    }
    return S2N_SUCCESS;
}

/* Enable the "tls" Upper Level Protocols (ULP) over TCP for this connection */
S2N_RESULT s2n_ktls_register_ulp(int fd)
{
    // todo see if this is already done
    int ret_val = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
    if (ret_val < 0) {
        fprintf(stderr, "ktls register upl failed 2 xxxxxxxxxxxxxx: %s\n", strerror(errno));
        return S2N_RESULT_ERROR;
    } else {
        /* fprintf(stderr, "ktls ulp enabled---------- \n"); */
    }

    return S2N_RESULT_OK;
}

// todo
// - RX mode
// - cleanup if intermediate steps fails
S2N_RESULT s2n_ktls_enable(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_EQ(conn->config->ktls_requested, true);

    /* RESULT_ENSURE_EQ(conn->managed_send_io, true); */
    /* RESULT_ENSURE_EQ(conn->managed_recv_io, true); */

    /* should not be called twice */
    RESULT_ENSURE_EQ(conn->ktls_enabled_send_io, false);
    RESULT_ENSURE_EQ(conn->ktls_enabled_recv_io, false);

    /* const struct s2n_socket_write_io_context *peer_socket_ctx = conn->send_io_context; */
    int fd = conn->sendfd;
    /* int fd = 8; */
    fprintf(stderr, "ktls upl for socket fd---------- %d\n", conn->sendfd);

    /* register the tls ULP */
    RESULT_GUARD(s2n_ktls_register_ulp(fd));

    /* set keys */
    RESULT_GUARD(s2n_ktls_set_keys(conn, fd));
    /* RESULT_GUARD(s2n_connection_ktls_rekey(conn)); */

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_connection_ktls_rekey(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);
    conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

    uint8_t         server_key_bytes[ 16 ] = "server key";
    struct s2n_blob server_key             = { 0 };
    server_key.size                        = 16;
    server_key.data                        = server_key_bytes;
    RESULT_ENSURE_REF(server_key.data);

    RESULT_ENSURE_EQ(16, server_key.size);
    RESULT_CHECKED_MEMCPY(conn->server_key, server_key.data, server_key.size);

    struct s2n_blob sequence_number;
    RESULT_GUARD_POSIX(s2n_blob_init(&sequence_number, conn->secure->server_sequence_number,
                                     sizeof(conn->secure->server_sequence_number)));
    RESULT_GUARD_POSIX(s2n_blob_zero(&sequence_number));

    struct s2n_blob iv;
    RESULT_GUARD_POSIX(s2n_blob_init(&iv, conn->secure->server_implicit_iv, sizeof(conn->secure->server_implicit_iv)));
    RESULT_GUARD_POSIX(s2n_blob_zero(&iv));

    RESULT_GUARD(s2n_ktls_tx_keys(conn, conn->sendfd, iv.data, sequence_number.data, conn->server_key));
    RESULT_GUARD(s2n_ktls_rx_keys(conn, conn->sendfd, iv.data, sequence_number.data, conn->server_key));

    return S2N_RESULT_OK;
}
