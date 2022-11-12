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

package com.illuminated_security.appliedcrypto.ae;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import javax.crypto.spec.SecretKeySpec;

import org.testng.annotations.Test;

import com.illuminated_security.appliedcrypto.block.AesCbcCipher;
import com.illuminated_security.appliedcrypto.block.AesCtrCipher;
import com.illuminated_security.appliedcrypto.hash.HMAC;
import com.illuminated_security.appliedcrypto.mac.ECBCMac;

public class EncryptThenMacTest {

    @Test
    public void testCCM() {
        var cipher = new EncryptThenMac(new AesCtrCipher(), new ECBCMac());
        var key = new SecretKeySpec(new byte[64], "AES");
        var message = "Hello, World!";
        var ciphertext = cipher.encrypt(key, message.getBytes(UTF_8));
        var plaintext = cipher.decrypt(key, ciphertext).orElseThrow();
        assertThat(plaintext).asString(UTF_8).isEqualTo(message);
    }

    @Test
    public void testCbcHmac() {
        var cipher = new EncryptThenMac(new AesCbcCipher(), new HMAC("SHA-256"));
        var key = new SecretKeySpec(new byte[64], "AES");
        var message = "Hello, World!";
        var ciphertext = cipher.encrypt(key, message.getBytes(UTF_8));
        var plaintext = cipher.decrypt(key, ciphertext).orElseThrow();
        assertThat(plaintext).asString(UTF_8).isEqualTo(message);
    }
}