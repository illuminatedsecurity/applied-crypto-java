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

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;

import com.illuminated_security.appliedcrypto.Utils;

public final class ChaCha20StreamCipher implements CpaSecureCipher {
    @Override
    public byte[] encrypt(SecretKey key, byte[] plaintext) {
        var nonce = Utils.secureRandomBytes(12);
        var ciphertext = process(key, nonce, plaintext);
        return Utils.concat(nonce, ciphertext);
    }

    @Override
    public Optional<byte[]> decrypt(SecretKey key, byte[] ciphertext) {
        if (ciphertext.length < 12) { return Optional.empty(); }
        var nonce = Arrays.copyOf(ciphertext, 12);
        ciphertext = Arrays.copyOfRange(ciphertext, 12, ciphertext.length);
        return Optional.of(process(key, nonce, ciphertext));
    }

    private static byte[] process(SecretKey key, byte[] nonce, byte[] data) {
        try {
            var cipher = Cipher.getInstance("ChaCha20");
            cipher.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 1));
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (GeneralSecurityException e) {
            throw new AssertionError(e);
        }
    }
}
