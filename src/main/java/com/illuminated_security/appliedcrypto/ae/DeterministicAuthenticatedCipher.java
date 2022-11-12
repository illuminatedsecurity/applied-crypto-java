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

/**
 * A cipher that achieves the security goal of Deterministic Authenticated Encryption (DAE). Note that this type is
 * not a subclass of {@link com.illuminated_security.appliedcrypto.stream.CpaSecureCipher} because DAE encryption is
 * not secure under a chosen plaintext attack.
 */
public interface DeterministicAuthenticatedCipher {
    byte[] encrypt(SecretKey key, byte[] plaintext, byte[]...assocData);
    Optional<byte[]> decrypt(SecretKey key, byte[] ciphertext, byte[]...assocData);
}
