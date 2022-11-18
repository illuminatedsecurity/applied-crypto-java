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

package com.illuminated_security.appliedcrypto.rsa;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;

import com.illuminated_security.appliedcrypto.Utils;
import com.illuminated_security.appliedcrypto.ae.AuthenticatedCipher;
import com.illuminated_security.appliedcrypto.ae.KeyWrapCipher;

public class HybridEncryption implements PublicKeyCipher {

    private final KeyWrapCipher publicKeyCipher;
    private final AuthenticatedCipher symmetricCipher;
    private final String symmetricAlgorithm;

    public HybridEncryption(KeyWrapCipher publicKeyCipher, AuthenticatedCipher symmetricCipher,
            String symmetricAlgorithm) {
        this.publicKeyCipher = publicKeyCipher;
        this.symmetricCipher = symmetricCipher;
        this.symmetricAlgorithm = symmetricAlgorithm;
    }

    @Override
    public byte[] encrypt(PublicKey key, byte[] plaintext) {
        var keyBytes = Utils.secureRandomBytes(16);
        var k = symmetricCipher.importKey(keyBytes, 0, 16);
        var c1 = publicKeyCipher.wrap(key, k);
        var c2 = symmetricCipher.encrypt(k, plaintext);
        return Utils.encodeWithLengthPrefix(c1, c2);
    }

    @Override
    public Optional<byte[]> decrypt(PrivateKey key, byte[] ciphertext) {
        var parts = Utils.decodeWithLengthPrefix(ciphertext);
        return publicKeyCipher.unwrap(key, parts[0], symmetricAlgorithm)
                .flatMap(k -> symmetricCipher.decrypt(k, parts[1]));
    }
}
