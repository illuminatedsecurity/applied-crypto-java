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

package com.illuminated_security.appliedcrypto.hash;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.illuminated_security.appliedcrypto.mac.PseudorandomFunction;

public final class HMAC implements PseudorandomFunction {
    private final String algorithm;

    public HMAC(String hashAlgorithm) {
        this.algorithm = "Hmac" + hashAlgorithm.replace("-", "");
    }

    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public byte[] authenticate(SecretKey key, byte[] message) {
        assert algorithm.equalsIgnoreCase(key.getAlgorithm());

        try {
            var mac = Mac.getInstance(algorithm);
            mac.init(key);
            return mac.doFinal(message);
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public SecretKey importKey(byte[] keyMaterial, int offset, int length) {
        return new SecretKeySpec(keyMaterial, offset, length, algorithm);
    }

    @Override
    public int tagLength() {
        try {
            return Mac.getInstance(algorithm).getMacLength();
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        }
    }
}
