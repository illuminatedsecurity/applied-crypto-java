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
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.illuminated_security.appliedcrypto.Utils;
import com.illuminated_security.appliedcrypto.hash.KeyDerivationFunction;

public final class RsaKem implements KeyEncapsulationMechanism {
    private final KeyDerivationFunction kdf;
    private final String demAlgorithm;
    private final byte[] salt;

    public RsaKem(KeyDerivationFunction kdf, String demAlgorithm, byte[] salt) {
        this.kdf = kdf;
        this.demAlgorithm = demAlgorithm;
        this.salt = salt;
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            var kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(3072);
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        }
    }

    @Override
    public EncapsulatedKey encapsulate(PublicKey pk, byte[] context) {
        var random = Utils.randomIntegerMod(((RSAPublicKey) pk).getModulus());
        var randomBytes = Utils.unsignedBytes(random);
        var demKeyMaterial = kdf.derive(randomBytes, salt, context, 32);
        var demKey = new SecretKeySpec(demKeyMaterial, demAlgorithm);
        var encapsulation = rsa(Cipher.ENCRYPT_MODE, pk, randomBytes);
        return new EncapsulatedKey(demKey, encapsulation);
    }

    @Override
    public Optional<SecretKey> decapsulate(PrivateKey privateKey, byte[] context, byte[] encapsulatedKey) {
        var random = rsa(Cipher.DECRYPT_MODE, privateKey, encapsulatedKey);
        var demKeyMaterial = kdf.derive(random, salt, context, 32);
        var demKey = new SecretKeySpec(demKeyMaterial, demAlgorithm);
        return Optional.of(demKey);
    }

    private static byte[] rsa(int mode, Key key, byte[] input) {
        try {
            var cipher = Cipher.getInstance("RSA/ECB/NoPadding");
            cipher.init(mode, key);
            return cipher.doFinal(input);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new AssertionError(e); // Cannot happen
        }
    }
}
