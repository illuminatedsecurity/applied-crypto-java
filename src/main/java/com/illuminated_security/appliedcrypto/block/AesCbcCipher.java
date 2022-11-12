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

package com.illuminated_security.appliedcrypto.block;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import com.illuminated_security.appliedcrypto.Utils;
import com.illuminated_security.appliedcrypto.stream.CpaSecureCipher;

public final class AesCbcCipher implements CpaSecureCipher {
    @Override
    public byte[] encrypt(SecretKey key, byte[] plaintext) {
        try {
            var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            var iv = cipher.getIV();
            assert iv.length == 16;
            var ciphertext = cipher.doFinal(plaintext);
            return Utils.concat(iv, ciphertext);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (GeneralSecurityException e) {
            throw new AssertionError(e);
        }
    }

    @Override
    public Optional<byte[]> decrypt(SecretKey key, byte[] ciphertext) {
        try {
            var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ciphertext, 0, 16));
            return Optional.of(cipher.doFinal(ciphertext, 16, ciphertext.length - 16));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (BadPaddingException e) {
            // NB: still vulnerable to padding oracle attack!
            // One possible fix is to return Optional.of(RandomUtils.secureRandomBytes(ciphertext.length - 16))
            // so that an attacker learns nothing about what caused the error.
            return Optional.empty();
        } catch (GeneralSecurityException e) {
            throw new AssertionError(e);
        }
    }
}
