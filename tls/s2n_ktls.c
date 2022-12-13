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

#include "s2n_ktls.h"

/*
 * Compares s2n_ktls_mode to see if they are equal.
 */
bool s2n_ktls_is_ktls_mode_eq(s2n_ktls_mode a, s2n_ktls_mode b)
{
    if (b == S2N_KTLS_MODE_DUPLEX) {
        return a == S2N_KTLS_MODE_DUPLEX;
    }
    if (b == S2N_KTLS_MODE_DISABLED) {
        return a == S2N_KTLS_MODE_DISABLED;
    }
    return a & b;
}

/*
 * TODO implement
 */
S2N_RESULT s2n_ktls_enable(struct s2n_connection *conn, s2n_ktls_mode mode)
{
    /* TODO perform managed_send_io and managed_recv_io checks */

    return S2N_RESULT_OK;
}
