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

#include "testlib/s2n_config_test_utils.h"
#include "crypto/s2n_fips.h"
#include "tls/s2n_tls.h"

/* TODO dont love this */
const int default_idx = 0;
const int default_fips_idx = 1;

static int s2n_override_default_policies_in_test(const struct s2n_security_policy *override_policy, int idx)
{
    POSIX_ENSURE(s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);
    struct s2n_security_policy_selection *default_policy = &security_policy_selection[idx];

    default_policy->security_policy = override_policy;
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
    /* TODO call this fn instead */
    /* s2n_enable_tls13(); */

    s2n_highest_protocol_version = S2N_TLS13;
    s2n_use_default_tls13_config_flag = true;
    // replace "default" with a tls13 policy
    if (s2n_is_in_fips_mode()) {
        s2n_override_default_policies_in_test(&security_policy_20240702, default_fips_idx);
    } else {
        s2n_override_default_policies_in_test(&security_policy_20240701, default_idx);
    }

    return S2N_SUCCESS;
}

/* Do NOT allow TLS1.3 to be negotiated, regardless of security policy.
 * This is NOT the default behavior, and this method is deprecated.
 *
 * Please consider using the default behavior and configuring
 * TLS1.2/TLS1.3 via explicit security policy instead.
 */
int s2n_disable_tls13_in_test()
{
    POSIX_ENSURE(s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);
    s2n_highest_protocol_version = S2N_TLS12;
    s2n_use_default_tls13_config_flag = false;
    // replace "default" with a tls12 policy
    if (s2n_is_in_fips_mode()) {
        s2n_override_default_policies_in_test(&security_policy_20240502, default_fips_idx);
    } else {
        s2n_override_default_policies_in_test(&security_policy_20240501, default_idx);
    }

    return S2N_SUCCESS;
}

/* Reset S2N to the default protocol version behavior.
 *
 * This method is intended for use in existing unit tests when the APIs
 * to enable/disable TLS1.3 have already been called.
 */
int s2n_reset_tls13_in_test()
{
    POSIX_ENSURE(s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);
    s2n_highest_protocol_version = S2N_TLS13;
    s2n_use_default_tls13_config_flag = true;
    // replace "default" with a tls13 policy
    if (s2n_is_in_fips_mode()) {
        s2n_override_default_policies_in_test(&security_policy_20240702, default_fips_idx);
    } else {
        s2n_override_default_policies_in_test(&security_policy_20240701, default_idx);
    }
    return S2N_SUCCESS;
}
