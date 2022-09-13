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

#include "s2n_test.h"

#include <string.h>
#include <stdio.h>

#include "api/s2n.h"

#include "testlib/s2n_testlib.h"

#include "tls/s2n_cipher_suites.h"
#include "stuffer/s2n_stuffer.h"
#include "crypto/s2n_cipher.h"
#include "utils/s2n_random.h"
#include "crypto/s2n_hmac.h"
#include "tls/s2n_record.h"
#include "tls/s2n_prf.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();


    // ------------------ algo
    EVP_CIPHER_CTX *evp_cipher_ctx = EVP_CIPHER_CTX_new();
    EXPECT_EQUAL(EVP_CIPHER_CTX_init(evp_cipher_ctx), 1);

    // ------------------ key
    /* uint8_t mac_key[] = "sample mac key"; */
    uint8_t iv_data[] = { 0 };
    struct s2n_blob iv = {.data = iv_data,.size = sizeof(iv_data) };

    uint8_t des3_key[] = "12345678901234567890123";
    struct s2n_blob des3 = {.data = des3_key,.size = sizeof(des3_key) };

    EXPECT_EQUAL(des3.size, 192 / 8);

    // ------------------ data
    //
    uint8_t plaintext[100] = { 0 };
    struct s2n_blob in = {.data = plaintext, .size = sizeof(plaintext)};
    in.size = 11;
    int data_size = 16;

    for( int i = 0 ; i < in.size; i++ ) {
        in.data[i] = 1;
    }
    in.data[data_size] = 101; // marker

    printf("\n------before----\n");
    for( int i = 0 ; i < 32; i++ ) {
        printf("%d ", in.data[i]);
    }
    printf("\n----------\n");



    // ------------------ encrypt
    /* EXPECT_EQUAL(EVP_CIPHER_CTX_set_padding(evp_cipher_ctx, 1), 0); */
    EXPECT_EQUAL(EVP_EncryptInit_ex(evp_cipher_ctx, EVP_des_ede3_cbc(), NULL, des3.data, NULL), 1);

    EXPECT_EQUAL(EVP_EncryptInit_ex(evp_cipher_ctx, NULL, NULL, NULL, iv.data), 1);
    int out_len = 0;
    EXPECT_EQUAL(EVP_EncryptUpdate(evp_cipher_ctx, in.data, &out_len, in.data, data_size), 1);
    /* EXPECT_EQUAL(EVP_EncryptUpdate(evp_cipher_ctx, in.data, &out_len, in.data, data_size), 1); */
    EXPECT_EQUAL(out_len, data_size);

    printf("\n----encrypt------\n");
    printf("out_len %d \n", out_len);
    for( int i = 0 ; i < 32; i++ ) {
        printf("%d ", in.data[i]);
    }

    printf("\n----------\n");
    for( int i = 0 ; i < out_len; i++ ) {
        printf("%d ", in.data[i]);
    }
    printf("\n----------\n");




    // ------------------ decrypt
    /* EXPECT_EQUAL(EVP_CIPHER_CTX_set_padding(evp_cipher_ctx, 1), 1); */
    EXPECT_EQUAL(EVP_DecryptInit_ex(evp_cipher_ctx, EVP_des_ede3_cbc(), NULL, des3.data, NULL), 1);

    EXPECT_EQUAL(EVP_DecryptInit_ex(evp_cipher_ctx, NULL, NULL, NULL, iv.data), 1);

    int len = 0;
    EXPECT_EQUAL(EVP_DecryptUpdate(evp_cipher_ctx, in.data, &len, in.data, data_size), 1);
    /* EXPECT_EQUAL(EVP_DecryptUpdate(evp_cipher_ctx, in.data, &len, in.data, data_size), 1); */

    printf("\n-----decrypt-----\n");
    printf("decrypt_out_len %d \n", len);
    for( int i = 0 ; i < 32; i++ ) {
        printf("%d ", in.data[i]);
    }
    printf("\n----------\n");


    /* struct s2n_connection *conn; */

    /* EXPECT_SUCCESS(s2n_disable_tls13_in_test()); */

    /* EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER)); */
    /* EXPECT_OK(s2n_get_public_random_data(&r)); */

    /* /1* Peer and we are in sync *1/ */
    /* conn->server = conn->secure; */
    /* conn->client = conn->secure; */

    /* /1* test the 3des cipher with a SHA1 hash *1/ */
    /* conn->secure->cipher_suite->record_alg = &s2n_record_alg_3des_sha; */
    /* EXPECT_SUCCESS(conn->secure->cipher_suite->record_alg->cipher->init(&conn->secure->server_key)); */
    /* EXPECT_SUCCESS(conn->secure->cipher_suite->record_alg->cipher->init(&conn->secure->client_key)); */
    /* EXPECT_SUCCESS(conn->secure->cipher_suite->record_alg->cipher->set_encryption_key(&conn->secure->server_key, &des3)); */
    /* EXPECT_SUCCESS(conn->secure->cipher_suite->record_alg->cipher->set_decryption_key(&conn->secure->client_key, &des3)); */
    /* EXPECT_SUCCESS(s2n_hmac_init(&conn->secure->client_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key))); */
    /* EXPECT_SUCCESS(s2n_hmac_init(&conn->secure->server_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key))); */
    /* conn->actual_protocol_version = S2N_TLS11; */

    /* /1* for (int i = 0; i <= S2N_DEFAULT_FRAGMENT_LENGTH + 1; i++) { *1/ */
    /* int i = 8; */
    /*     struct s2n_blob in = {.data = random_data,.size = i }; */
    /*     int bytes_written; */

    /*     EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out)); */
    /*     EXPECT_SUCCESS(bytes_written = s2n_record_write(conn, TLS_APPLICATION_DATA, &in)); */

    /*     if (i <= S2N_DEFAULT_FRAGMENT_LENGTH) { */
    /*         EXPECT_EQUAL(bytes_written, i); */
    /*     } else { */
    /*         /1* application data size of intended fragment size + 1 should only send max fragment *1/ */
    /*         EXPECT_EQUAL(bytes_written, S2N_DEFAULT_FRAGMENT_LENGTH); */
    /*     } */

    /*     uint16_t predicted_length = bytes_written + 1 + 20 + 8; */
    /*     if (predicted_length % 8) { */
    /*         predicted_length += (8 - (predicted_length % 8)); */
    /*     } */
    /*     EXPECT_EQUAL(conn->out.blob.data[0], TLS_APPLICATION_DATA); */
    /*     EXPECT_EQUAL(conn->out.blob.data[1], 3); */
    /*     EXPECT_EQUAL(conn->out.blob.data[2], 2); */
    /*     EXPECT_EQUAL(conn->out.blob.data[3], (predicted_length >> 8) & 0xff); */
    /*     EXPECT_EQUAL(conn->out.blob.data[4], predicted_length & 0xff); */

    /*     /1* The data should be encrypted *1/ */
    /*     if (bytes_written > 10) { */
    /*         EXPECT_NOT_EQUAL(memcmp(conn->out.blob.data + 5, random_data, bytes_written), 0); */
    /*     } */

    /*     /1* Copy the encrypted out data to the in data *1/ */
    /*     EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in)); */
    /*     EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in)); */
    /*     EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->header_in, 5)); */
    /*     EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->in, s2n_stuffer_data_available(&conn->out))); */

    /*     /1* Let's decrypt it *1/ */
    /*     uint8_t content_type; */
    /*     uint16_t fragment_length; */
    /*     EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length)); */
    /*     EXPECT_SUCCESS(s2n_record_parse(conn)); */
    /*     EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA); */
    /*     EXPECT_EQUAL(fragment_length, predicted_length); */

    /*     EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in)); */
    /*     EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in)); */
    /* /1* } *1/ */

    /* EXPECT_SUCCESS(conn->secure->cipher_suite->record_alg->cipher->destroy_key(&conn->secure->server_key)); */
    /* EXPECT_SUCCESS(conn->secure->cipher_suite->record_alg->cipher->destroy_key(&conn->secure->client_key)); */
    /* EXPECT_SUCCESS(s2n_connection_free(conn)); */

    END_TEST();
}
