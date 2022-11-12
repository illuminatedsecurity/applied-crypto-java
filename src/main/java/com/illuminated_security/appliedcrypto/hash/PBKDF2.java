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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public final class PBKDF2 implements KeyDerivationFunction {
    @Override
    public byte[] derive(byte[] inputKeyMaterial, byte[] salt, byte[] context, int outputByteLength) {
        assert context == null;
        var buffer = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(inputKeyMaterial));
        char[] password = new char[buffer.length()];
        buffer.get(password);

        try {
            var pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return pbkdf2.generateSecret(new PBEKeySpec(password, salt, 100_000, outputByteLength)).getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvalidKeySpecException e) {
            throw new AssertionError(e);
        }
    }
}
