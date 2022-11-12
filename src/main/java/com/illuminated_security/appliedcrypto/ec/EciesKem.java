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

package com.illuminated_security.appliedcrypto.ec;

import static java.nio.charset.StandardCharsets.*;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Optional;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.illuminated_security.appliedcrypto.Utils;
import com.illuminated_security.appliedcrypto.hash.HKDF;
import com.illuminated_security.appliedcrypto.hash.HMAC;
import com.illuminated_security.appliedcrypto.hash.KeyDerivationFunction;
import com.illuminated_security.appliedcrypto.rsa.KeyEncapsulationMechanism;

public class EciesKem implements KeyEncapsulationMechanism {
    private static final byte[] SALT = "ECIES-KEM-X25519".getBytes(UTF_8);

    final KeyPairGenerator keyPairGenerator;
    final KeyAgreement keyAgreement;
    final KeyFactory keyFactory;
    final KeyDerivationFunction kdf = new HKDF(new HMAC("SHA-256"));
    final String demAlgorithm;

    public EciesKem(String demAlgorithm) throws NoSuchAlgorithmException {
        this.demAlgorithm = demAlgorithm;
        this.keyAgreement = KeyAgreement.getInstance("X25519");
        this.keyFactory = KeyFactory.getInstance("X25519");
        this.keyPairGenerator = KeyPairGenerator.getInstance("X25519");
    }


    @Override
    public EncapsulatedKey encapsulate(PublicKey publicKey, byte[] context) {
        var ephemeralKeys = keyPairGenerator.generateKeyPair();
        var demKey = deriveKey(ephemeralKeys.getPrivate(), publicKey,
                kdfContext(ephemeralKeys.getPublic(), context));
        return new EncapsulatedKey(demKey, ephemeralKeys.getPublic().getEncoded());
    }

    @Override
    public Optional<SecretKey> decapsulate(PrivateKey privateKey, byte[] context, byte[] encapsulatedKey) {
        try {
            var epk = keyFactory.generatePublic(new X509EncodedKeySpec(encapsulatedKey));
            return Optional.of(deriveKey(privateKey, epk, kdfContext(epk, context)));
        } catch (InvalidKeySpecException e) {
            return Optional.empty();
        }
    }

    static byte[] kdfContext(PublicKey epk, byte[] suppliedContext) {
        return Utils.concat(epk.getEncoded(), suppliedContext);
    }

    SecretKey deriveKey(PrivateKey privateKey, PublicKey publicKey, byte[] context) {
        byte[] sharedSecret = x25519(privateKey, publicKey);
        byte[] demKeyBytes = kdf.derive(sharedSecret, SALT, context, 32);
        var demKey = new SecretKeySpec(demKeyBytes, demAlgorithm);
        Arrays.fill(sharedSecret, (byte) 0);
        Arrays.fill(demKeyBytes, (byte) 0);

        return demKey;
    }

    byte[] x25519(PrivateKey privateKey, PublicKey publicKey) {
        try {
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);
            return keyAgreement.generateSecret();
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
