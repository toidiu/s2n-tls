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

#include "tls/s2n_auth_selection.h"

#include "api/s2n.h"
#include "crypto/s2n_fips.h"
#include "crypto/s2n_rsa_pss.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_signature_scheme.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    // This works for s2n_config_new() because we create a new s2n_config object
    // which is then configured based on (default, default_fips, testing_override)
    // Note, we still need a way to toggle to testing_override here.
    /* EXPECT_SUCCESS(s2n_disable_tls13_in_test()); */
    /* struct s2n_config *config = s2n_config_new(); */
    /* EXPECT_NOT_NULL(config); */

    // s2n_connection_new uses the static config objects.
    // when testing_override is set, it will attempt to use these configs objects
    // if these testing_override are not initialized, we get a seg fault
    //
    // This creates a new connection with the default config set on it.
    // We get the default config by calling s2n_fetch_default_config() in s2n_connection_new().
    // s2n_fetch_default_config() returns static configs. (default, default_fips, testing_override)
    // testing_override is controlled by calls such as s2n_disable_tls13_in_test()
    //
    // we dont want to modify the static "default" config
    // s2n_config *s2n_fetch_default_config(), returns a pointer to a config
    // we need an object to return a pointer to... this means the object needs to be in scope
    // this means that the testing_override config object needs to be in the production scope.
    // which means it cant live in testing only.
    //
    // we need an indicator to select a testing_override config from s2n_fetch_default_config
    // s2n_use_testing_override: bool
    // this bool and toggle logic also needs to live in production scope.
    //
    /* EXPECT_SUCCESS(s2n_disable_tls13_in_test()); */
    struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
    EXPECT_NOT_NULL(conn);


    END_TEST();

    return 0;
}
