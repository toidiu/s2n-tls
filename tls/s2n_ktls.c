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

#include "tls/s2n_ktls.h"

#include <linux/tls.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include "error/s2n_errno.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_crypto.h"
#include "utils/s2n_result.h"
#include "utils/s2n_safety_macros.h"
#include "utils/s2n_socket.h"

#define TLS_ULP      "tls"
#define TLS_ULP_SIZE sizeof(TLS_ULP)
/* value declared in netinet/tcp.h */
#define SOL_TCP 6 /* TCP level */

/* Depending on OS and configuration it might not be possible to enable kTLS. This
 * however is not fatal and s2n can continue to operate.
 *
 * This macro captures the non-fatal nature of a kTLS operation failing by
 * returning S2N_RESULT_OK on failure.
 */
#define RESULT_GUARD_KTLS_OK(result) __S2N_ENSURE(s2n_result_is_ok(result), return S2N_RESULT_OK)

bool s2n_ktls_is_ktls_mode_send(s2n_ktls_mode ktls_mode)
{
    return ktls_mode & S2N_KTLS_MODE_SEND;
}

bool s2n_ktls_is_ktls_mode_recv(s2n_ktls_mode ktls_mode)
{
    return ktls_mode & S2N_KTLS_MODE_RECV;
}

S2N_RESULT s2n_ktls_set_crypto_info(
        s2n_ktls_mode ktls_mode,
        int fd,
        uint8_t implicit_iv[S2N_TLS_MAX_IV_LEN],
        uint8_t sequence_number[S2N_TLS_SEQUENCE_NUM_LEN])
{
    uint8_t key[16] = { 0 };

    struct tls12_crypto_info_aes_gcm_128 crypto_info;

    /* AES_GCM_128 specific configuration */
    crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
    RESULT_CHECKED_MEMCPY(crypto_info.salt, implicit_iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
    RESULT_CHECKED_MEMCPY(crypto_info.rec_seq, sequence_number, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
    RESULT_CHECKED_MEMCPY(crypto_info.key, key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);

    /* TLS1.2 specific configuration */
    crypto_info.info.version = TLS_1_2_VERSION;
    RESULT_CHECKED_MEMCPY(crypto_info.iv, implicit_iv, TLS_CIPHER_AES_GCM_128_IV_SIZE);

    int tls_mode;
    /* configure socket and enable kTLS */
    if (s2n_ktls_is_ktls_mode_send(ktls_mode)) {
        tls_mode = TLS_RX;
    } else if (s2n_ktls_is_ktls_mode_send(ktls_mode)) {
        tls_mode = TLS_RX;
    } else {
        /* unreachable: ktls_mode should only be S2N_KTLS_MODE_SEND or S2N_KTLS_MODE_RECV */
        return S2N_RESULT_ERROR;
    }

    RESULT_GUARD_POSIX(setsockopt(fd, SOL_TLS, tls_mode, &crypto_info, sizeof(crypto_info)));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ktls_enable_impl(struct s2n_connection *conn, s2n_ktls_mode ktls_mode, int fd)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE(s2n_ktls_is_ktls_mode_recv(ktls_mode) || s2n_ktls_is_ktls_mode_send(ktls_mode), S2N_ERR_SAFETY);

    /* register the tls ULP */
    RESULT_GUARD_POSIX(setsockopt(fd, SOL_TCP, TCP_ULP, TLS_ULP, TLS_ULP_SIZE));

    /* set crypto info and enable kTLS on the socket */
    struct s2n_crypto_parameters *crypto_param;
    if (conn->mode == S2N_SERVER) {
        crypto_param = conn->server;
    } else {
        crypto_param = conn->client;
    }
    RESULT_GUARD(s2n_ktls_set_crypto_info(ktls_mode, fd, crypto_param->server_implicit_iv, crypto_param->server_sequence_number));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ktls_validate(struct s2n_connection *conn, s2n_ktls_mode ktls_mode)
{
    RESULT_ENSURE_REF(conn);

    /* TODO support TLS1.3
     *
     * TLS1.3 support requires sending the KeyUpdate message when the cryptographic
     * KeyLimits are met. However, this is currently only possible by applying a
     * kernel patch to support this functionality.
     */
    RESULT_ENSURE_EQ(conn->actual_protocol_version, S2N_TLS12);

    /* TODO Add validation for cipher suites */

    /* confirm that the application requested ktls */
    RESULT_ENSURE(s2n_config_is_ktls_requested(conn->config, ktls_mode), S2N_ERR_SAFETY);

    /* kTLS I/O functionality is managed by s2n-tls. kTLS cannot be enabled
     * if the application sets custom I/O.
     */
    if (s2n_ktls_is_ktls_mode_send(ktls_mode) && !conn->managed_send_io) {
        return S2N_RESULT_ERROR;
    }
    if (s2n_ktls_is_ktls_mode_recv(ktls_mode) && !conn->managed_recv_io) {
        return S2N_RESULT_ERROR;
    }

    /* confim kTLS isn't enabled already */
    RESULT_ENSURE_EQ(s2n_connection_matches_ktls_mode(conn, ktls_mode), false);

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ktls_enable(struct s2n_connection *conn, s2n_ktls_mode ktls_mode)
{
    RESULT_ENSURE_REF(conn);
    RESULT_GUARD_KTLS_OK(s2n_ktls_validate(conn, ktls_mode));

    int fd;
    if (s2n_ktls_is_ktls_mode_recv(ktls_mode)) {
        /* retrieve the recv fd */
        const struct s2n_socket_write_io_context *peer_socket_ctx = conn->recv_io_context;
        fd = peer_socket_ctx->fd;
        RESULT_GUARD_KTLS_OK(s2n_ktls_enable_impl(conn, S2N_KTLS_MODE_RECV, fd));
    }

    if (s2n_ktls_is_ktls_mode_send(ktls_mode)) {
        /* retrieve the send fd */
        const struct s2n_socket_write_io_context *peer_socket_ctx = conn->send_io_context;
        fd = peer_socket_ctx->fd;
        RESULT_GUARD_KTLS_OK(s2n_ktls_enable_impl(conn, S2N_KTLS_MODE_SEND, fd));
    }

    /* Note: kTLS has been enabled on the socket. Any subsequent errors are likely to be fatal. */

    /* configure kTLS specific I/O callback and context. */
    RESULT_GUARD(s2n_connection_set_ktls_write_fd(conn, fd));
    RESULT_GUARD(s2n_connection_set_ktls_read_fd(conn, fd));

    /* mark kTLS enabled on the connection */
    RESULT_GUARD(s2n_connection_mark_ktls_enabled(conn, ktls_mode));

    return S2N_RESULT_OK;
}

int s2n_ktls_write_fn(void *io_context, const uint8_t *buf, uint32_t len)
{
    POSIX_ENSURE_REF(io_context);
    POSIX_ENSURE_REF(buf);

    int wfd = ((struct s2n_ktls_write_io_context *) io_context)->fd;
    if (wfd < 0) {
        errno = EBADF;
        POSIX_BAIL(S2N_ERR_BAD_FD);
    }

    /* On success, the number of bytes written is returned. On failure, -1 is
     * returned and errno is set appropriately. */
    ssize_t result = write(wfd, buf, len);
    POSIX_ENSURE_INCLUSIVE_RANGE(INT_MIN, result, INT_MAX);
    return result;
}

int s2n_ktls_read_fn(void *io_context, uint8_t *buf, uint32_t len)
{
    POSIX_ENSURE_REF(io_context);
    POSIX_ENSURE_REF(buf);
    int rfd = ((struct s2n_ktls_read_io_context *) io_context)->fd;
    if (rfd < 0) {
        errno = EBADF;
        POSIX_BAIL(S2N_ERR_BAD_FD);
    }

    /* On success, the number of bytes read is returned. On failure, -1 is
     * returned and errno is set appropriately. */
    ssize_t result = read(rfd, buf, len);
    POSIX_ENSURE_INCLUSIVE_RANGE(INT_MIN, result, INT_MAX);
    return result;
}
