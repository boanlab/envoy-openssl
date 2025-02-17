/*
 * Copyright (C) 2022 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/rand.h>
#include <ossl.h>
#include "log.h"

extern "C" int RAND_bytes(uint8_t *buf, size_t len) {
  //// bssl_compat_info("[+]SSL_METHOD::RAND_bytes");
  if (ossl.ossl_RAND_bytes((unsigned char *)buf, (int)len) <= 0)
    return 0;

	return 1;
}
