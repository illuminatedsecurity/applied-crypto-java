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

import static java.nio.charset.StandardCharsets.UTF_8;

import javax.crypto.SecretKey;

import com.illuminated_security.appliedcrypto.hash.HKDF;
import com.illuminated_security.appliedcrypto.hash.HMAC;
import com.illuminated_security.appliedcrypto.mac.PseudorandomFunction;

public class CascadeMessageAuthenticator implements MultipleInputMessageAuthenticator {
    private final PseudorandomFunction prf;
    private final HKDF hkdf = new HKDF(new HMAC("SHA-256"));

    public CascadeMessageAuthenticator(PseudorandomFunction prf) {
        this.prf = prf;
    }

    @Override
    public SecretKey importKey(byte[] keyMaterial, int offset, int length) {
        return prf.importKey(keyMaterial, offset, length);
    }

    @Override
    public int tagLength() {
        return prf.tagLength();
    }

    @Override
    public byte[] authenticate(SecretKey key, byte[]... chunks) {
        var keyMaterial = hkdf.expand(key, "CascadeMac-SubKeyDerivation".getBytes(UTF_8), 64);
        var macKey = prf.importKey(keyMaterial, 0, 32);
        var finKey = prf.importKey(keyMaterial, 32, 64);

        byte[] tag = new byte[prf.tagLength()];
        for (byte[] chunk : chunks) {
            tag = prf.authenticate(macKey, chunk);
            macKey = prf.importKey(tag, 0, tag.length);
        }

        return prf.authenticate(finKey, tag);
    }
}
