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

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class InsecureRsaEncryption {

    public KeyPair generateKeyPair() {
        try {
            var kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(3072);
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        }
    }

    public byte[] encrypt(PublicKey key, byte[] plaintext) {
        try {
            var cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(plaintext);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new UnsupportedOperationException(e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new AssertionError(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private Optional<byte[]> decrypt(PrivateKey key, byte[] ciphertext) {
        try {
            var cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return Optional.of(cipher.doFinal(ciphertext));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new UnsupportedOperationException(e);
        } catch (IllegalBlockSizeException e) {
            throw new AssertionError(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (BadPaddingException e) {
            return Optional.empty();
        }
    }
}
