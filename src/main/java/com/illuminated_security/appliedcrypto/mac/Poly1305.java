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

import java.math.BigInteger;
import java.util.Arrays;

import javax.crypto.SecretKey;

import com.illuminated_security.appliedcrypto.Utils;

/**
 * The Poly1305 MAC as described in <a href="https://www.rfc-editor.org/rfc/rfc8439">RFC 8439</a>.
 * A fresh key must be chosen for each message, making this MAC only really useful as part of an
 * {@link com.illuminated_security.appliedcrypto.ae.AuthenticatedCipher}.
 *
 * @implNote This class is not secure against timing attacks.
 */
public final class Poly1305 implements OneTimeAuthenticator {
    private static final BigInteger CLAMP =  new BigInteger("0ffffffc0ffffffc0ffffffc0fffffff", 16);
    private static final BigInteger P = BigInteger.TWO.pow(130).subtract(BigInteger.valueOf(5));

    @Override
    public byte[] authenticate(SecretKey key, byte[] message) {
        assert key.getEncoded().length == 32;
        byte[] rBytes = Utils.reverse(Arrays.copyOfRange(key.getEncoded(), 0, 16));
        byte[] sBytes = Utils.reverse(Arrays.copyOfRange(key.getEncoded(), 16, 32));
        BigInteger r = new BigInteger(1, rBytes).and(CLAMP);
        BigInteger s = new BigInteger(1, sBytes);

        byte[] block = new byte[17];
        BigInteger t = BigInteger.ZERO;
        for (int i = 0; i < message.length; i += 16) {
            BigInteger a = loadBlock(message, i, block);
            t = t.add(a).multiply(r).mod(P);
        }
        t = t.add(s);
        return Arrays.copyOf(Utils.reverse(t.toByteArray()), 16);
    }

    BigInteger loadBlock(byte[] data, int offset, byte[] block) {
        Arrays.fill(block, (byte) 0);
        int n = Math.min(16, data.length - offset);
        System.arraycopy(data, offset, block, 0, n);
        block[n] = 1; // add 2^(n*8)
        return new BigInteger(1, Utils.reverse(block));
    }
}
