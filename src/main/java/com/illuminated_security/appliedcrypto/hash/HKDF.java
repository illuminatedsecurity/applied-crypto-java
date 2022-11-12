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

import java.io.ByteArrayOutputStream;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.illuminated_security.appliedcrypto.Utils;

public final class HKDF implements KeyDerivationFunction {

    private final HMAC hmac;

    public HKDF(HMAC hmac) {
        this.hmac = hmac;
    }

    @Override
    public byte[] derive(byte[] inputKeyMaterial, byte[] salt, byte[] context, int outputByteLength) {
        var prk = extract(inputKeyMaterial, salt);
        return expand(prk, context, outputByteLength);
    }

    public SecretKey extract(byte[] inputKeyMaterial, byte[] salt) {
        return new SecretKeySpec(
                hmac.authenticate(new SecretKeySpec(salt, hmac.getAlgorithm()), inputKeyMaterial), hmac.getAlgorithm());
    }

    public byte[] expand(SecretKey prk, byte[] context, int outputByteLength) {
        byte[] counter = new byte[] { 0 };
        byte[] lastBlock = new byte[0];
        var out = new ByteArrayOutputStream();
        while (out.size() < outputByteLength) {
            if (++counter[0] == 0) { throw new IllegalStateException("counter overflow"); }
            lastBlock = hmac.authenticate(prk, Utils.concat(lastBlock, context, counter));
            out.writeBytes(lastBlock);
        }
        return out.toByteArray();
    }
}
