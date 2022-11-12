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

import static org.assertj.core.api.Assertions.*;

import java.security.KeyPairGenerator;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;

import org.testng.annotations.Test;

public class SchnorrIdentificationProtocolTest {

    @Test
    public void testIt() throws Exception {
        var kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(2048);
        var keys = kpg.generateKeyPair();

        var prover = new SchnorrIdentificationProtocol.SchnorrProver((DSAPrivateKey) keys.getPrivate());
        var verifier = new SchnorrIdentificationProtocol.SchnorrVerifier((DSAPublicKey) keys.getPublic());

        var commitment = prover.commit();
        var challenge = verifier.challenge(commitment);
        var response = prover.response(challenge);

        assertThat(verifier.accept(response)).isTrue();
    }

}