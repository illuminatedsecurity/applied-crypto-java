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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Optional;

import javax.crypto.SecretKey;

import software.pando.crypto.nacl.ByteSlice;
import software.pando.crypto.nacl.SecretBox;

public final class SecretBoxCipher implements AuthenticatedCipher {
    @Override
    public SecretKey importKey(byte[] keyMaterial, int offset, int length) {
        return SecretBox.key(ByteSlice.of(keyMaterial, offset, length));
    }

    @Override
    public byte[] encrypt(SecretKey key, byte[] plaintext) {
        try (var box = SecretBox.encrypt(key, plaintext);
             var out = new ByteArrayOutputStream()) {
            box.writeTo(out);
            return out.toByteArray();
        } catch (IOException e) {
            throw new AssertionError("Unexpected IOException", e);
        }
    }

    @Override
    public Optional<byte[]> decrypt(SecretKey key, byte[] ciphertext) {
        try (var box = SecretBox.readFrom(new ByteArrayInputStream(ciphertext))) {
            return Optional.of(box.decrypt(key));
        } catch (IOException e) {
            throw new AssertionError(e);
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
