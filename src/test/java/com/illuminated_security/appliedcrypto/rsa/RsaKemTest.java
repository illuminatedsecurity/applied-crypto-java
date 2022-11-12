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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.RSAKeyGenParameterSpec;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.illuminated_security.appliedcrypto.hash.HKDF;
import com.illuminated_security.appliedcrypto.hash.HMAC;

public class RsaKemTest {
    private KeyPair keyPair;

    @BeforeClass
    public void generateKeys() throws Exception {
        var kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(3)));
        keyPair = kpg.generateKeyPair();
    }

    @Test(invocationCount = 10)
    public void testWorks() throws Exception {
        RsaKem kem = new RsaKem(new HKDF(new HMAC("SHA-256")), "AES", "Test".getBytes());
        var encapKey = kem.encapsulate(keyPair.getPublic(), "Test".getBytes(UTF_8));
        var demKey = kem.decapsulate(keyPair.getPrivate(), "Test".getBytes(UTF_8), encapKey.getEncapsulation())
                        .orElseThrow();
        assertThat(demKey).isEqualTo(encapKey.getDemKey());
    }
}