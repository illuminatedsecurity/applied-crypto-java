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

package com.illuminated_security.appliedcrypto.mac;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class ECBCMac implements PseudorandomFunction {

    @Override
    public byte[] authenticate(SecretKey key, byte[] message) {
        int mid = key.getEncoded().length / 2;
        var macKey = new SecretKeySpec(key.getEncoded(), 0,   mid, "AES");
        var finKey = new SecretKeySpec(key.getEncoded(), mid, mid, "AES");

        try {
            var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, macKey, new IvParameterSpec(new byte[16]));
            var ciphertext = cipher.doFinal(message);
            var tag = Arrays.copyOfRange(ciphertext, ciphertext.length - 16, ciphertext.length);

            // Re-encrypt the tag with the second key. Note that CBC encryption of a single block with a 0 IV is
            // identical to plain AES block cipher encryption, so long as we discard the second block (padding)
            cipher.init(Cipher.ENCRYPT_MODE, finKey, new IvParameterSpec(new byte[16]));
            tag = Arrays.copyOf(cipher.doFinal(tag), 16);
            return tag;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (GeneralSecurityException e) {
            throw new AssertionError(e);
        }
    }
}
