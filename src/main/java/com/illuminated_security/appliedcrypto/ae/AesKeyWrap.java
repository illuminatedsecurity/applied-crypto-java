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

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public final class AesKeyWrap implements KeyWrapCipher {

    @Override
    public byte[] wrap(Key wrapKey, SecretKey keyToBeWrapped) {
        try {
            var cipher = Cipher.getInstance("AESWrap");
            cipher.init(Cipher.WRAP_MODE, wrapKey);
            return cipher.wrap(keyToBeWrapped);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvalidKeyException | IllegalBlockSizeException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public Optional<SecretKey> unwrap(Key unwrapKey, byte[] wrappedKey, String unwrappedKeyAlgorithm) {
        try {
            var cipher = Cipher.getInstance("AESWrap");
            cipher.init(Cipher.UNWRAP_MODE, unwrapKey);
            try {
                return Optional.of((SecretKey) cipher.unwrap(wrappedKey, unwrappedKeyAlgorithm, Cipher.SECRET_KEY));
            } catch (InvalidKeyException e) {
                // AES KeyWrap implementation throws InvalidKeyException if tag verification fails or unwrapped key
                // is invalid.
                return Optional.empty();
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
