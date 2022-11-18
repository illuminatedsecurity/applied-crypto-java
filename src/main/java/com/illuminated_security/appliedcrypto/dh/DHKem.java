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

package com.illuminated_security.appliedcrypto.dh;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Optional;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.illuminated_security.appliedcrypto.Utils;
import com.illuminated_security.appliedcrypto.hash.KeyDerivationFunction;
import com.illuminated_security.appliedcrypto.rsa.KeyEncapsulationMechanism;

public class DHKem implements KeyEncapsulationMechanism {

    private final String dhAlgorithm;
    private final String keyGenAlgorithm;
    private final AlgorithmParameterSpec parameters;
    private final KeyDerivationFunction kdf;
    private final byte[] salt;
    final String demAlgorithm;

    DHKem(String dhAlgorithm, String keyGenAlgorithm, AlgorithmParameterSpec parameters, KeyDerivationFunction kdf,
            byte[] salt, String demAlgorithm) {
        this.dhAlgorithm = dhAlgorithm;
        this.keyGenAlgorithm = keyGenAlgorithm;
        this.parameters = parameters;
        this.kdf = kdf;
        this.salt = salt.clone();
        this.demAlgorithm = demAlgorithm;
    }

    public DHKem(DHParameterSpec parameters, KeyDerivationFunction kdf, byte[] salt, String demAlgorithm) {
        this("DiffieHellman", "DiffieHellman", parameters, kdf, salt, demAlgorithm);
    }

    public KeyPair generateKeyPair() {
        try {
            var kpg = KeyPairGenerator.getInstance(keyGenAlgorithm);
            kpg.initialize(parameters);
            return kpg.generateKeyPair();
        } catch ( NoSuchAlgorithmException
                | InvalidAlgorithmParameterException e) {
            throw new UnsupportedOperationException(e);
        }
    }

    @Override
    public EncapsulatedKey encapsulate(PublicKey publicKey, byte[] context) {
        var ephemeralKeys = generateKeyPair();
        var kdfContext = Utils.concat(ephemeralKeys.getPublic().getEncoded(), context);
        var demKey = deriveKey(ephemeralKeys.getPrivate(), publicKey, kdfContext);
        return new EncapsulatedKey(demKey, ephemeralKeys.getPublic().getEncoded());
    }

    @Override
    public Optional<SecretKey> decapsulate(PrivateKey privateKey, byte[] context, byte[] encapsulatedKey) {
        var epk = decodePublicKey(encapsulatedKey);
        var kdfContext = Utils.concat(encapsulatedKey, context);
        var demKey = deriveKey(privateKey, epk, kdfContext);
        return Optional.of(demKey);
    }

    PublicKey decodePublicKey(byte[] key) {
        try {
            var kf = KeyFactory.getInstance(keyGenAlgorithm);
            return kf.generatePublic(new X509EncodedKeySpec(key));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new UnsupportedOperationException(e);
        }
    }

    SecretKey deriveKey(PrivateKey privateKey, PublicKey publicKey, byte[] context) {
        byte[] sharedSecret = new byte[0], keyMaterial = new byte[0];
        try {
            var dh = KeyAgreement.getInstance(dhAlgorithm);
            dh.init(privateKey);
            dh.doPhase(publicKey, true);
            sharedSecret = dh.generateSecret();
            keyMaterial = kdf.derive(sharedSecret, salt, context, 32);
            return new SecretKeySpec(keyMaterial, demAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } finally {
            Arrays.fill(sharedSecret, (byte) 0);
            Arrays.fill(keyMaterial, (byte) 0);
        }
    }
}
