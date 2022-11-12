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

import static com.illuminated_security.appliedcrypto.hash.CollisionResistantHash.SHA512;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;

import com.illuminated_security.appliedcrypto.Utils;
import com.illuminated_security.appliedcrypto.auth.SchnorrIdentificationProtocol.SchnorrProver;
import com.illuminated_security.appliedcrypto.auth.SchnorrIdentificationProtocol.SchnorrVerifier;

public class FiatShamirSignature implements DigitalSignature {
    // TODO: define a SigmaIdentificationProtocol interface. We need to somehow surface that it only uses public coins

    @Override
    public byte[] sign(PrivateKey signingKey, byte[] message) {
        var prover = new SchnorrProver((DSAPrivateKey) signingKey);
        var commitment = prover.commit();
        var challenge = SHA512.hash(Utils.concat(commitment, message));
        return prover.response(challenge);
    }

    @Override
    public boolean verify(PublicKey verificationKey, byte[] message, byte[] signature) {
        var verifier = new SchnorrVerifier((DSAPublicKey) verificationKey);
        // TODO: figure out how to inject the hash into the verifier.
        return verifier.accept(signature);
    }
}
