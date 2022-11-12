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

package com.illuminated_security.appliedcrypto.auth;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

public class SchnorrIdentificationProtocol implements SigmaProtocol {

    public static KeyPair keyPair(DSAParams params) {
        try {
            var kpg = KeyPairGenerator.getInstance("DSA");
            kpg.initialize(new DSAParameterSpec(params.getP(), params.getQ(), params.getG()));
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    public static class SchnorrProver implements Prover {

        private final DSAPrivateKey staticKey;
        private KeyPair ephemeralKeyPair;

        public SchnorrProver(DSAPrivateKey staticKey) {
            this.staticKey = staticKey;
        }

        @Override
        public byte[] commit() {
            ephemeralKeyPair = keyPair(staticKey.getParams());
            return ephemeralKeyPair.getPublic().getEncoded();
        }

        @Override
        public byte[] response(byte[] challenge) {
            // s = k + xe (mod q)
            try {
                var e = new BigInteger(1, challenge);
                var k = ((DSAPrivateKey) ephemeralKeyPair.getPrivate()).getX();
                var x = staticKey.getX();
                var q = staticKey.getParams().getQ();
                var s = k.add(x.multiply(e)).mod(q);

                return s.toByteArray();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    static boolean paramsEqual(DSAParams a, DSAParams b) {
        return Objects.equals(a.getG(), b.getG()) && Objects.equals(a.getP(), b.getP()) && Objects.equals(a.getQ(), b.getQ());
    }

    public static class SchnorrVerifier implements Verifier {

        private final DSAPublicKey publicKey;
        private DSAPublicKey commitment;
        private DSAPrivateKey challenge;

        public SchnorrVerifier(DSAPublicKey publicKey) {
            this.publicKey = publicKey;
        }

        @Override
        public byte[] challenge(byte[] commitment) {
            try {
                var kf = KeyFactory.getInstance("DSA");
                this.commitment = (DSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(commitment));

                if (!paramsEqual(this.commitment.getParams(), publicKey.getParams())) {
                    throw new IllegalArgumentException("Commitment has different parameters to PK");
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            this.challenge = (DSAPrivateKey) keyPair(publicKey.getParams()).getPrivate();
            return challenge.getX().toByteArray();
        }

        @Override
        public boolean accept(byte[] response) {
            // g^s =? u * h^c
            var g = publicKey.getParams().getG();
            var p = publicKey.getParams().getP();
            var s = new BigInteger(1, response);
            var lhs = g.modPow(s, p);
            var rhs = commitment.getY().multiply(publicKey.getY().modPow(challenge.getX(), p)).mod(p);

            return lhs.equals(rhs);
        }
    }
}
