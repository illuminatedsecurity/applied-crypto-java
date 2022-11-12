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

import java.security.MessageDigest;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public interface MessageAuthenticator extends OneTimeAuthenticator {
    default SecretKey importKey(byte[] keyMaterial, int offset, int length) {
        return new SecretKeySpec(keyMaterial, offset, length, "AES");
    }
    byte[] authenticate(SecretKey key, byte[] message);
    default boolean verify(SecretKey key, byte[] message, byte[] tag) {
        var computedTag = authenticate(key, message);
        return MessageDigest.isEqual(computedTag, tag);
    }

    default int tagLength() {
        return 16;
    }
}
