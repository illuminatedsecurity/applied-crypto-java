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
import static org.assertj.core.api.Assertions.*;

import java.security.KeyPairGenerator;

import org.testng.annotations.Test;

public class EciesKemTest {

    @Test
    public void testBasic() throws Exception {
        var keyPair = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        var kem = new EciesKem("AES");
        var context = "Test".getBytes(UTF_8);

        var encapKey = kem.encapsulate(keyPair.getPublic(), context);
        var decapKey = kem.decapsulate(keyPair.getPrivate(), context, encapKey.getEncapsulation())
                .orElseThrow();

        assertThat(decapKey).isEqualTo(encapKey.getDemKey());
    }

}