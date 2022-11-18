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

public final class KemDemEncryption implements PublicKeyCipher {
    private static final byte[] EMPTY_CONTEXT = new byte[0];
    private final KeyEncapsulationMechanism kem;
    private final AuthenticatedCipher dem;

    public KemDemEncryption(KeyEncapsulationMechanism kem, AuthenticatedCipher dem) {
        this.kem = kem;
        this.dem = dem;
    }

    public byte[] encrypt(PublicKey key, byte[] plaintext) {
        var encapKey = kem.encapsulate(key, EMPTY_CONTEXT);
        var ciphertext = dem.encrypt(encapKey.demKey(), plaintext);
        return Utils.encodeWithLengthPrefix(encapKey.encapsulation(), ciphertext);
    }

    public Optional<byte[]> decrypt(PrivateKey privateKey, byte[] ciphertext) {
        var parts = Utils.decodeWithLengthPrefix(ciphertext);
        assert parts.length == 2;

        return kem.decapsulate(privateKey, EMPTY_CONTEXT, parts[0])
                .flatMap(demKey -> dem.decrypt(demKey, parts[1]));
    }
}
