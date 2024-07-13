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

#include <stdlib.h>

#include "api/s2n.h"
#include "crypto/s2n_fips.h"
#include "crypto/s2n_pq.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls13.h"

static S2N_RESULT test_connection(struct s2n_connection *server, struct s2n_connection *client)
{
    /* EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server, "default")); */
    /* EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client, "default")); */

    DEFER_CLEANUP(struct s2n_stuffer input, s2n_stuffer_free);
    DEFER_CLEANUP(struct s2n_stuffer output, s2n_stuffer_free);
    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));

    EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, server));
    EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&output, &input, client));

    EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

    RESULT_ENSURE_EQ(server->actual_protocol_version, S2N_TLS12);
    RESULT_ENSURE_EQ(client->actual_protocol_version, S2N_TLS12);

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST_NO_INIT();

    EXPECT_SUCCESS(s2n_init());

    /* Test for s2n_config_new() and tls 1.3 behavior */
    {
        printf("\n----------------- STARTING TEST ------------");

        /* config */
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_NOT_NULL(config->security_policy);
        struct s2n_cert_chain_and_key *chain_and_key = NULL;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));

        /* connection */
        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_blinding(client, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));

        EXPECT_SUCCESS(s2n_connection_set_config(server, config));
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));

        EXPECT_OK(test_connection(server, client));
    };

    {
        /* EXPECT_SUCCESS(s2n_disable_tls13_in_test()); */
        /* EXPECT_SUCCESS(s2n_enable_tls13_in_test()); */
        /* EXPECT_NOT_NULL(config = s2n_config_new()); */
        /* /1* EXPECT_EQUAL(config->security_policy, tls13_security_policy); *1/ */
        /* EXPECT_SUCCESS(s2n_config_free(config)); */
    };

    EXPECT_SUCCESS(s2n_cleanup());
    END_TEST_NO_INIT();
}
