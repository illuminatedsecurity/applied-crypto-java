/*
 * Copyright 2022 Neil Madden.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.illuminated_security.appliedcrypto.ae;

import java.util.Optional;

import javax.crypto.SecretKey;

public interface AuthenticatedCipherWithAD extends AuthenticatedCipher {
    byte[] encrypt(SecretKey key, byte[] plaintext, byte[] assocData);
    Optional<byte[]> decrypt(SecretKey key, byte[] ciphertext, byte[] assocData);

    @Override
    default byte[] encrypt(SecretKey key, byte[] plaintext) {
        return encrypt(key, plaintext, new byte[0]);
    }

    @Override
    default Optional<byte[]> decrypt(SecretKey key, byte[] ciphertext) {
        return decrypt(key, ciphertext, new byte[0]);
    }
}
