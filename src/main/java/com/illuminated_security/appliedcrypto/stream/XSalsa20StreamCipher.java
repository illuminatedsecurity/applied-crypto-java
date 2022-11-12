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

package com.illuminated_security.appliedcrypto.stream;

import java.util.Arrays;
import java.util.Optional;

import javax.crypto.SecretKey;

import com.illuminated_security.appliedcrypto.Utils;

import software.pando.crypto.nacl.ByteSlice;
import software.pando.crypto.nacl.Subtle;

public final class XSalsa20StreamCipher implements CpaSecureCipher {
    @Override
    public SecretKey importKey(byte[] keyMaterial, int offset, int length) {
        return Subtle.streamXSalsa20Key(ByteSlice.of(keyMaterial, offset, length));
    }

    @Override
    public byte[] encrypt(SecretKey key, byte[] plaintext) {
        byte[] ciphertext = plaintext.clone();
        try (var cipher = Subtle.streamXSalsa20(key)) {
            byte[] nonce = cipher.nonce();
            cipher.process(ByteSlice.of(ciphertext)); // Encrypt in-place
            return Utils.concat(nonce, ciphertext);
        }
    }

    @Override
    public Optional<byte[]> decrypt(SecretKey key, byte[] ciphertext) {
        byte[] nonce = Arrays.copyOf(ciphertext, 24);
        byte[] plaintext = Arrays.copyOfRange(ciphertext, 24, ciphertext.length);
        try (var cipher = Subtle.streamXSalsa20(key, nonce)) {
            cipher.process(ByteSlice.of(plaintext));
            return Optional.of(plaintext);
        }
    }
}
