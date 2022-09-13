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
    uint8_t iv_data[] = { 0 };
    struct s2n_blob iv = {.data = iv_data,.size = sizeof(iv_data) };

    uint8_t des3_key[] = "12345678901234567890123";
    struct s2n_blob des3 = {.data = des3_key,.size = sizeof(des3_key) };

    EXPECT_EQUAL(des3.size, 192 / 8);

    // ------------------ data
    uint8_t plaintext_cpy[100] = { 0 };
    struct s2n_blob in_cpy = {.data = plaintext_cpy, .size = sizeof(plaintext_cpy)};

    uint8_t plaintext[100] = { 0 };
    struct s2n_blob in = {.data = plaintext, .size = sizeof(plaintext)};

    int data_size = 11;
    int blk_size_multiple = 16;

    for( int i = 0 ; i < data_size; i++ ) {
        in.data[i] = i;
    }
    in.data[blk_size_multiple] = 111; // marker

    printf("\n------before----\n");
    for( int i = 0 ; i < 32; i++ ) {
        printf("%03d ", in.data[i]);
    }


    // ------------------ encrypt
    EXPECT_EQUAL(EVP_EncryptInit_ex(evp_cipher_ctx, EVP_des_ede3_cbc(), NULL, des3.data, NULL), 1);

    /* EXPECT_EQUAL(EVP_CIPHER_CTX_set_padding(evp_cipher_ctx, 0), 1); */
    EXPECT_EQUAL(EVP_CIPHER_CTX_set_padding(evp_cipher_ctx, 1), 1);

    EXPECT_EQUAL(EVP_EncryptInit_ex(evp_cipher_ctx, NULL, NULL, NULL, iv.data), 1);
    int out_len = 0;
    EXPECT_EQUAL(EVP_EncryptUpdate(evp_cipher_ctx, in.data, &out_len, in.data, 16), 1);
    EXPECT_EQUAL(out_len, blk_size_multiple);

    printf("\n----encrypt------\n");
    printf("out_len %d \n", out_len);
    for( int i = 0 ; i < 32; i++ ) {
        printf("%03d ", in.data[i]);
    }




    // ------------------ decrypt
    /* EXPECT_EQUAL(EVP_DecryptInit_ex(evp_cipher_ctx, EVP_des_ede3_cbc(), NULL, des3.data, NULL), 1); */
    EXPECT_EQUAL(EVP_DecryptInit_ex(evp_cipher_ctx, NULL, NULL, NULL, iv.data), 1);

    /* EXPECT_EQUAL(EVP_CIPHER_CTX_set_padding(evp_cipher_ctx, 0), 1); */
    EXPECT_EQUAL(EVP_CIPHER_CTX_set_padding(evp_cipher_ctx, 1), 1);

    int len = 0;
    EXPECT_EQUAL(EVP_DecryptUpdate(evp_cipher_ctx, in.data, &len, in.data, blk_size_multiple), 1);

    printf("\n-----decrypt-----\n");
    printf("decrypt_out_len %d \n", len);
    for( int i = 0 ; i < 32; i++ ) {
        printf("%03d ", in.data[i]);
    }

    for( int i = 0 ; i < 32; i++ ) {
        printf("%03d ", in_cpy.data[i]);
    }
    printf("\n----------\n");


    END_TEST();
}
