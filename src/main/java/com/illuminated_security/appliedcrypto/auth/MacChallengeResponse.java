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

import java.security.Key;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.SecretKey;

import com.illuminated_security.appliedcrypto.Utils;
import com.illuminated_security.appliedcrypto.mac.MessageAuthenticator;

public class MacChallengeResponse implements ChallengeResponseProtocol {
    private final Map<String, SecretKey> macKeys = new ConcurrentHashMap<>();
    private final MessageAuthenticator mac;

    public MacChallengeResponse(MessageAuthenticator mac) {
        this.mac = mac;
    }

    @Override
    public void register(String username, Key key) {
        macKeys.put(username, (SecretKey) key);
    }

    @Override
    public byte[] challenge(String username) {
        return Utils.secureRandomBytes(20);
    }

    @Override
    public boolean response(String username, byte[] challenge, byte[] response) {
        var macKey = macKeys.getOrDefault(username, mac.importKey(Utils.secureRandomBytes(32), 0, 32));
        return mac.verify(macKey, challenge, response);
    }
}
