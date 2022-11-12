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

import java.util.Arrays;
import java.util.Optional;

import javax.crypto.SecretKey;

import com.illuminated_security.appliedcrypto.Utils;
import com.illuminated_security.appliedcrypto.mac.PseudorandomFunction;
import com.illuminated_security.appliedcrypto.stream.CpaSecureCipher;

public final class EncryptThenCascadeMac implements AuthenticatedCipherWithAD {
    private final CpaSecureCipher cipher;
    private final CascadeMessageAuthenticator mac;

    public EncryptThenCascadeMac(CpaSecureCipher cipher, PseudorandomFunction prf) {
        this.cipher = cipher;
        this.mac = new CascadeMessageAuthenticator(prf);
    }

    @Override
    public byte[] encrypt(SecretKey key, byte[] plaintext, byte[] assocData) {
        int mid = key.getEncoded().length / 2;
        var encKey = cipher.importKey(key.getEncoded(), 0, mid);
        var macKey = mac.importKey(key.getEncoded(), mid, mid);

        var ciphertext = cipher.encrypt(encKey, plaintext);
        var tag = mac.authenticate(macKey, assocData, ciphertext);

        return Utils.concat(ciphertext, tag);
    }

    @Override
    public Optional<byte[]> decrypt(SecretKey key, byte[] ciphertext, byte[] assocData) {
        int mid = key.getEncoded().length / 2;
        var encKey = cipher.importKey(key.getEncoded(), 0, mid);
        var macKey = mac.importKey(key.getEncoded(), mid, mid);

        var tag = Arrays.copyOfRange(ciphertext, ciphertext.length - mac.tagLength(), ciphertext.length);
        ciphertext = Arrays.copyOf(ciphertext, ciphertext.length - mac.tagLength());

        if (!mac.verify(macKey, tag, assocData, ciphertext)) {
            return Optional.empty();
        }

        return cipher.decrypt(encKey, ciphertext);
    }
}
