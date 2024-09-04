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

// To audit "default" usage we only need to check usage of the array
// security_policy_selection. There are 3 cases we need to care about:
//
// 1) Explicit use via conn/config_set_cipher_preferences().
//   - Can detect and fix.
//
// 2) The 'static' config (default, fips, tls13) initialized from s2n_init()
//   - Can detect and fix.
//   - Confirm only a single call to s2n_config_defaults_init()
//
// 3) Implicit use via s2n_config_new/_minimal().
//   - TODO: disable all initialization of 'static' config and expect NULL?
//   - Permanent code?: Do not set default `if (!s2n_in_unit_test())` -> expect NULL
//   - Other alternatives:
//   - Hard. Used only if there is no call to set_cipher_preferences() later.
//   - Clutter. Add another API for tests: s2n_config_new_with_policy()
//
// Other audit:
// - check usage of `security_policy_selection` array in s2n_security_policies.c
// - check usage of `security_policy_selection` array in tests
//
// PR
// - make the detection as clean as possible. then the remaining changes will be automated changes

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
    BEGIN_TEST();

    // Requires `dbail = false/true` in s2n_config_init()
    // This is so that the call to s2n_config_new() doesn't fail
    //
    // Then only explicit calls via set_cipher_preferences will bail
    if (true) {
        // 1) Explicit use via config_set_cipher_preferences().
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                    s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
        };

        // 1) Explicit use via config_set_cipher_preferences().
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                    s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);

            EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_cipher_preferences(config, "default"), S2N_ERR_INVALID_SECURITY_POLICY);
        };

        // 1) Explicit use via connection_set_cipher_preferences().
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_cipher_preferences(conn, "default"), S2N_ERR_INVALID_SECURITY_POLICY);
        };

        // 2) The 'static' config (default, fips, tls13) initialized from s2n_init()
        //   - Confirm only a single call to s2n_config_defaults_init()
        //   - Fixed: removing static config usage in s2n_connection_preference_test.c
        {
            s2n_wipe_static_configs();
            EXPECT_FAILURE_WITH_ERRNO(s2n_config_defaults_init(), S2N_ERR_INVALID_SECURITY_POLICY);
        };
    };

    // Requires commenting out `s2n_config_setup_default(config)` from s2n_config_init()
    //
    // Then the static configs and default configs will be NULL and result in a
    // NULL exception.

    // TODO: QUESTION
    // A connections can be setup with default config (s2n_fetch_default_config
    // called in s2n_connection_new).
    //
    // Q: Do we need to worry about connection being initialized with 'static'
    // default config (s2n_fetch_default_config)?
    //
    // If we don't initialize the static configs, all s2n_connection_new() calls
    // fail. This will result in a massive change/audit. Is there a better way
    // to detect this?
    //
    // A: Seems like not since negotiate doesnt work if a config is not set.
    //
    if (false) {
        // 3) The 'static' config (default, fips, tls13) initialized from s2n_init()
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                    s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);

            EXPECT_NULL(config->security_policy);
        };

        // 3) The 'static' config (default, fips, tls13) initialized from s2n_init()
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                    s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20240501"));

            EXPECT_NOT_NULL(config->security_policy);
        };

        // 3) The 'static' config (default, fips, tls13) initialized from s2n_init()
        {
            /* config */
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                    s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);

            /* connection */
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));

            EXPECT_FAILURE(s2n_connection_set_config(server, config));
        };

        // 3) The 'static' config (default, fips, tls13) initialized from s2n_init()
        {
            /* config */
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                    s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20240501"));

            /* connection */
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));

            EXPECT_SUCCESS(s2n_connection_set_config(server, config));
        };

        // 3) The 'static' config (default, fips, tls13) initialized from s2n_init()
        {
            /* config */
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                    s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20240501"));

            struct s2n_cert_chain_and_key *chain_and_key = NULL;
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                    S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));

            /* connection */
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client);
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            EXPECT_SUCCESS(s2n_connection_set_blinding(client, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));

            EXPECT_SUCCESS(s2n_connection_set_config(server, config));
            EXPECT_SUCCESS(s2n_connection_set_config(client, config));

            EXPECT_OK(test_connection(server, client));
        };
    };

    EXPECT_SUCCESS(s2n_cleanup());
    END_TEST();
}
