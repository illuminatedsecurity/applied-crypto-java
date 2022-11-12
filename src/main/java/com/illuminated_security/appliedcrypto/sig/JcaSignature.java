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

package com.illuminated_security.appliedcrypto.sig;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class JcaSignature implements DigitalSignature {
    private final String algorithm;

    public JcaSignature(String algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    public byte[] sign(PrivateKey signingKey, byte[] message) {
        try {
            var sig = Signature.getInstance(algorithm);
            sig.initSign(signingKey);
            sig.update(message);
            return sig.sign();
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (SignatureException e) {
            throw new AssertionError(e);
        }
    }

    @Override
    public boolean verify(PublicKey verificationKey, byte[] message, byte[] signature) {
        try {
            var sig = Signature.getInstance(algorithm);
            sig.initVerify(verificationKey);
            sig.update(message);
            return sig.verify(signature);
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            return false;
        }
    }
}
