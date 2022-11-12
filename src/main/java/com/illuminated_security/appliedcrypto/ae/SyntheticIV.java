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

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.cryptomator.siv.SivMode;
import org.cryptomator.siv.UnauthenticCiphertextException;

public class SyntheticIV implements DeterministicAuthenticatedCipher {
    private static final SivMode AES_SIV = new SivMode();

    @Override
    public byte[] encrypt(SecretKey key, byte[] plaintext, byte[]... assocData) {
        var macKey = new SecretKeySpec(key.getEncoded(), 0, 16, "AES");
        var encKey = new SecretKeySpec(key.getEncoded(), 16, 16, "AES");
        return AES_SIV.encrypt(encKey, macKey, plaintext, assocData);
    }

    @Override
    public Optional<byte[]> decrypt(SecretKey key, byte[] ciphertext, byte[]... assocData) {
        var macKey = new SecretKeySpec(key.getEncoded(), 0, 16, "AES");
        var encKey = new SecretKeySpec(key.getEncoded(), 16, 16, "AES");

        try {
            return Optional.of(AES_SIV.decrypt(encKey, macKey, ciphertext, assocData));
        } catch (UnauthenticCiphertextException e) {
            return Optional.empty();
        } catch (IllegalBlockSizeException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
