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

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;

import javax.crypto.spec.SecretKeySpec;

import org.testng.annotations.Test;

public class AesSingleBlockCipherTest {

    @Test
    public void testWorks() {
        var aes = new AesSingleBlockCipher();
        var key = new SecretKeySpec(new byte[16], "AES");
        var ciphertext = aes.encrypt(key, "Yellow Submarine".getBytes(StandardCharsets.UTF_8));
        var plaintext = aes.decrypt(key, ciphertext).orElseThrow();
        assertThat(plaintext).asString().isEqualTo("Yellow Submarine");
    }

    @Test
    public void testTampering() {
        var aes = new AesSingleBlockCipher();
        var key = new SecretKeySpec(new byte[16], "AES");
        var ciphertext = aes.encrypt(key, "Yellow Submarine".getBytes(StandardCharsets.UTF_8));
        ciphertext[4] ^= 0x01;
        var plaintext = aes.decrypt(key, ciphertext).orElseThrow();
        assertThat(plaintext).asString().isNotEqualTo("Yellow Submarine");
    }
}