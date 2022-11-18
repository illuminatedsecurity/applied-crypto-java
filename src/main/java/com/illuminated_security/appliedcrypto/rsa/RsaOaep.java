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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.MGF1ParameterSpec;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource.PSpecified;

import com.illuminated_security.appliedcrypto.ae.KeyWrapCipher;

public final class RsaOaep implements KeyWrapCipher {

    private static final OAEPParameterSpec OAEP_PARAMS =
            new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSpecified.DEFAULT);

    @Override
    public byte[] wrap(Key wrapKey, SecretKey keyToBeWrapped) {
        try {
            var cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.WRAP_MODE, wrapKey, OAEP_PARAMS);
            return cipher.wrap(keyToBeWrapped);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (IllegalBlockSizeException e) {
            throw new AssertionError(e);
        }
    }

    @Override
    public Optional<SecretKey> unwrap(Key unwrapKey, byte[] wrappedKey, String keyAlgorithm) {
        try {
            var cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.UNWRAP_MODE, unwrapKey, OAEP_PARAMS);
            try {
                return Optional.of((SecretKey) cipher.unwrap(wrappedKey, keyAlgorithm, Cipher.SECRET_KEY));
            } catch (InvalidKeyException e) {
                // At this stage, InvalidKeyException really means BadPaddingException
                return Optional.empty();
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
