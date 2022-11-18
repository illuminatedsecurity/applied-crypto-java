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

import java.util.Arrays;
import java.util.Optional;

import javax.crypto.SecretKey;

import com.illuminated_security.appliedcrypto.Utils;

public class MisuseResistantAuthenticatedCipher implements AuthenticatedCipherWithAD {
    private final DeterministicAuthenticatedCipher cipher;

    public MisuseResistantAuthenticatedCipher(DeterministicAuthenticatedCipher cipher) {
        this.cipher = cipher;
    }

    @Override
    public byte[] encrypt(SecretKey key, byte[] plaintext, byte[] assocData) {
        byte[] nonce = Utils.secureRandomBytes(20);
        return Utils.concat(nonce, cipher.encrypt(key, plaintext, assocData, nonce));
    }

    @Override
    public Optional<byte[]> decrypt(SecretKey key, byte[] ciphertext, byte[] assocData) {
        byte[] nonce = Arrays.copyOf(ciphertext, 20);
        ciphertext = Arrays.copyOfRange(ciphertext, 20, ciphertext.length);
        return cipher.decrypt(key, ciphertext, assocData, nonce);
    }
}
