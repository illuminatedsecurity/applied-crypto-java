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

import java.security.MessageDigest;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.illuminated_security.appliedcrypto.Utils;
import com.illuminated_security.appliedcrypto.hash.HKDF;
import com.illuminated_security.appliedcrypto.hash.HMAC;
import com.illuminated_security.appliedcrypto.hash.KeyDerivationFunction;
import com.illuminated_security.appliedcrypto.hash.PBKDF2;

public class BearerAuthentication {
    private final Map<String, UserHash> hashes = new ConcurrentHashMap<>();
    private final KeyDerivationFunction kdf;

    private BearerAuthentication(KeyDerivationFunction kdf) {
        this.kdf = kdf;
    }

    public static BearerAuthentication forHighEntropySecrets() {
        return new BearerAuthentication(new HKDF(new HMAC("SHA-256")));
    }

    public static BearerAuthentication forPasswords() {
        return new BearerAuthentication(new PBKDF2());
    }

    public void register(String username, byte[] bearerCredential) {
        var salt = Utils.secureRandomBytes(16);
        var digest = kdf.derive(bearerCredential, salt, null, 32);
        hashes.put(username, new UserHash(salt, digest));
    }

    public boolean authenticate(String username, byte[] bearerCredential) {
        var userHash = hashes.getOrDefault(username, new UserHash(new byte[16], new byte[32]));
        var computedHash = kdf.derive(bearerCredential, userHash.salt, null, 32);
        return MessageDigest.isEqual(computedHash, userHash.hash);
    }

    private static class UserHash {
        final byte[] salt;
        final byte[] hash;

        private UserHash(byte[] salt, byte[] hash) {
            this.salt = salt;
            this.hash = hash;
        }
    }
}
