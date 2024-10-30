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

#include "testlib/s2n_config_utils.h"

#include "testlib/s2n_testlib.h"
#include "tls/s2n_tls.h"

/* Forward declarations for testing */
int s2n_config_init(struct s2n_config *config);
int s2n_config_cleanup(struct s2n_config *config);

static struct s2n_config s2n_default_tls13_config = { 0 };
static struct s2n_config s2n_default_tls12_config = { 0 };

S2N_RESULT s2n_config_setup_for_testing(struct s2n_config *config)
{
    switch (s2n_config_override_flag) {
        case S2N_CONFIG_OVERRIDE_TLS_13:
            /* Supports TLS 1.3 */
            RESULT_GUARD_POSIX(s2n_config_set_cipher_preferences(config, "20240503"));
            break;
        case S2N_CONFIG_OVERRIDE_TLS_12:
            /* Supports TLS 1.2 */
            RESULT_GUARD_POSIX(s2n_config_set_cipher_preferences(config, "20240501"));
            break;
        case S2N_CONFIG_NO_OVERRIDE:
            break;
        default:
            return S2N_RESULT_ERROR;
    }

    return S2N_RESULT_OK;
}

/* Called from BEGIN_TEST */
int s2n_init_for_testing(void)
{
    /* Supports TLS 1.3 */
    POSIX_GUARD(s2n_config_init(&s2n_default_tls13_config));
    POSIX_GUARD(s2n_config_set_cipher_preferences(&s2n_default_tls13_config, "20240503"));
    POSIX_GUARD(s2n_config_load_system_certs(&s2n_default_tls13_config));

    /* Supports TLS 1.2 */
    POSIX_GUARD(s2n_config_init(&s2n_default_tls12_config));
    POSIX_GUARD(s2n_config_set_cipher_preferences(&s2n_default_tls12_config, "20240501"));
    POSIX_GUARD(s2n_config_load_system_certs(&s2n_default_tls12_config));

    return S2N_SUCCESS;
}

/* Called from END_TEST */
int s2n_cleanup_for_testing(void)
{
    s2n_config_cleanup(&s2n_default_tls13_config);
    s2n_config_cleanup(&s2n_default_tls12_config);

    return S2N_SUCCESS;
}

/* Allow TLS1.3 to be negotiated, and use the default TLS1.3 security policy.
 * This is NOT the default behavior, and this method is deprecated.
 *
 * Please consider using the default behavior and configuring
 * TLS1.2/TLS1.3 via explicit security policy instead.
 */
int s2n_enable_tls13_in_test()
{
    /* Update setup function and static config used for testing */
    POSIX_GUARD_RESULT(s2n_config_update_overrides_for_testing(&s2n_default_tls13_config));

    /* Originally added to enable support TLS 1.3 support, s2n_enable_tls13, was
     * deprecated in favor of using security policy. This usage in testing allows
     * us to de-duplicate the logic.
     */
#ifdef S2N_DIAGNOSTICS_PUSH_SUPPORTED
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
    return s2n_enable_tls13();
#ifdef S2N_DIAGNOSTICS_POP_SUPPORTED
    #pragma GCC diagnostic pop
#endif
}

/* Do NOT allow TLS1.3 to be negotiated, regardless of security policy.
 * This is NOT the default behavior, and this method is deprecated.
 *
 * Please consider using the default behavior and configuring
 * TLS1.2/TLS1.3 via explicit security policy instead.
 */
int s2n_disable_tls13_in_test()
{
    s2n_highest_protocol_version = S2N_TLS12;
    s2n_config_override_flag = S2N_CONFIG_OVERRIDE_TLS_12;

    /* Revert setup function and static config used for testing */
    POSIX_GUARD_RESULT(s2n_config_update_overrides_for_testing(&s2n_default_tls12_config));

    return S2N_SUCCESS;
}

/* Reset S2N to the default protocol version behavior.
 *
 * This method is intended for use in existing unit tests when the APIs
 * to enable/disable TLS1.3 have already been called.
 */
int s2n_reset_tls13_in_test()
{
    s2n_highest_protocol_version = S2N_TLS13;
    s2n_config_override_flag = S2N_CONFIG_NO_OVERRIDE;

    return S2N_SUCCESS;
}
