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

package com.illuminated_security.appliedcrypto.pkae;

import static java.nio.charset.StandardCharsets.*;
import static org.assertj.core.api.Assertions.*;

import java.security.KeyPairGenerator;

import org.testng.annotations.Test;

import com.illuminated_security.appliedcrypto.hash.HKDF;
import com.illuminated_security.appliedcrypto.hash.HMAC;
import com.illuminated_security.appliedcrypto.rsa.RsaKem;
import com.illuminated_security.appliedcrypto.sig.Rsa15Signature;

public class SignedKeyBlobAuthenticatedKemTest {

    @Test
    public void testIt() throws Exception {
        var kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        var kemKeys = kpg.generateKeyPair();
        var sigKeys = kpg.generateKeyPair();

        var kem = new RsaKem(new HKDF(new HMAC("SHA-256")), "AES", new byte[32]);
        var sig = new Rsa15Signature();
        var authKem = new SignedKeyBlobAuthenticatedKem(kem, sig);

        var encapKey = authKem.encapsulate(sigKeys, kemKeys.getPublic(), "test".getBytes(UTF_8));
        var decapKey = authKem.decapsulate(kemKeys, sigKeys.getPublic(), "test".getBytes(UTF_8),
                encapKey.encapsulation()).orElseThrow();

        assertThat(decapKey).isEqualTo(encapKey.demKey());
    }

}