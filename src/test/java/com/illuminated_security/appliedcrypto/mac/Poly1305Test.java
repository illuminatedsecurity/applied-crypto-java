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

package com.illuminated_security.appliedcrypto.mac;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.math.BigInteger;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.assertj.core.api.Assertions;
import org.testng.annotations.Test;

public class Poly1305Test {

    @Test
    public void shouldMatchRfc7539TestVector() {
        var key = decodeKey("85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:" +
                "01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b");
        var message = "Cryptographic Forum Research Group".getBytes(UTF_8);
        var tag = new Poly1305().authenticate(key, message);
        Assertions.assertThat(tag).asHexString().isEqualToIgnoringCase("a8061dc1305136c6c22b8baf0c0127a9");
    }

    private static SecretKey decodeKey(String hex) {
        return new SecretKeySpec(parseHex(hex, 32), "Poly1305");
    }

    private static byte[] parseHex(String hex, int length) {
        var integer = new BigInteger(hex.replaceAll("[^0-9a-fA-F]+", ""), 16);
        var bytes = integer.toByteArray();
        return Arrays.copyOfRange(bytes, bytes.length - length, bytes.length);
    }
}