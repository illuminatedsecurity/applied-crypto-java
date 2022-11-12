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

import static java.nio.charset.StandardCharsets.*;

import java.security.Key;
import java.util.Arrays;
import java.util.Optional;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public final class DeterministicAEKeyWrap implements KeyWrapCipher {
    private final DeterministicAuthenticatedCipher daeCipher;

    public DeterministicAEKeyWrap(DeterministicAuthenticatedCipher daeCipher) {
        this.daeCipher = daeCipher;
    }

    @Override
    public byte[] wrap(Key wrapKey, SecretKey keyToBeWrapped) {
        return daeCipher.encrypt((SecretKey) wrapKey, keyToBeWrapped.getEncoded(),
                keyToBeWrapped.getAlgorithm().getBytes(UTF_8));
    }

    @Override
    public Optional<SecretKey> unwrap(Key unwrapKey, byte[] wrappedKey, String unwrappedKeyAlgorithm) {
        return daeCipher.decrypt((SecretKey) unwrapKey, wrappedKey, unwrappedKeyAlgorithm.getBytes(UTF_8))
                .map(keyBytes -> {
                    var key = new SecretKeySpec(keyBytes, unwrappedKeyAlgorithm);
                    Arrays.fill(keyBytes, (byte)0);
                    return key;
                });
    }
}
