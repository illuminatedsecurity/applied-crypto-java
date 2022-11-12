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
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Optional;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.illuminated_security.appliedcrypto.RandomUtils;
import com.illuminated_security.appliedcrypto.hash.KeyDerivationFunction;

public class RsaKem implements KeyEncapsulationMechanism {
    private final KeyDerivationFunction kdf;
    private final String demAlgorithm;
    private final byte[] salt;

    public RsaKem(KeyDerivationFunction kdf, String demAlgorithm, byte[] salt) {
        this.kdf = kdf;
        this.demAlgorithm = demAlgorithm;
        this.salt = salt;
    }

    @Override
    public EncapsulatedKey encapsulate(PublicKey publicKey, byte[] context) {
        var pk = (RSAPublicKey) publicKey;
        var random = RandomUtils.randomIntegerMod(pk.getModulus());
        var randomBytes = trimLeadingZero(random.toByteArray());
        var demKeyMaterial = kdf.derive(randomBytes, salt, context, 32);
        var demKey = new SecretKeySpec(demKeyMaterial, demAlgorithm);

        try {
            var cipher = Cipher.getInstance("RSA/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, pk);
            var ciphertext = cipher.doFinal(randomBytes);
            return new EncapsulatedKey(demKey, ciphertext);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new AssertionError(e);
        }
    }

    private static byte[] trimLeadingZero(byte[] intBytes) {
        if (intBytes.length % 2 != 0 && intBytes[0] == 0) {
            return Arrays.copyOfRange(intBytes, 1, intBytes.length);
        }
        return intBytes;
    }

    @Override
    public Optional<SecretKey> decapsulate(PrivateKey privateKey, byte[] context, byte[] encapsulatedKey) {
        try {
            var cipher = Cipher.getInstance("RSA/ECB/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            var random = cipher.doFinal(encapsulatedKey);
            var demKeyMaterial = kdf.derive(random, salt, context, 32);
            var demKey = new SecretKeySpec(demKeyMaterial, demAlgorithm);

            return Optional.of(demKey);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (IllegalBlockSizeException e) {
            throw new AssertionError(e);
        } catch (BadPaddingException e) {
            return Optional.empty();
        }
    }
}
