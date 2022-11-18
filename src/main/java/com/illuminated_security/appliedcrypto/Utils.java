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

package com.illuminated_security.appliedcrypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class Utils {
    private static final SecureRandom SECURE_RANDOM;
    static {
        SecureRandom tmp;
        try { tmp = SecureRandom.getInstance("NativePRNGNonBlocking"); }
        catch (NoSuchAlgorithmException e) { tmp = new SecureRandom(); }
        SECURE_RANDOM = tmp;
    }

    public static byte[] concat(byte[]... values) {
        var out = new ByteArrayOutputStream();
        for (var value : values) {
            out.writeBytes(value);
        }
        return out.toByteArray();
    }

    public static byte[] encodeWithLengthPrefix(byte[]... values) {
        var out = new ByteArrayOutputStream();
        for (var value : values) {
            out.write(value.length >>> 24);
            out.write(value.length >>> 16);
            out.write(value.length >>> 8);
            out.write(value.length);
            out.writeBytes(value);
        }
        return out.toByteArray();
    }

    public static byte[][] decodeWithLengthPrefix(byte[] data) {
        List<byte[]> blocks = new ArrayList<>();
        var in = new ByteArrayInputStream(data);
        while (in.available() > 0) {
            var len = in.read() << 24 | in.read() << 16 | in.read() << 8 | in.read();
            var block = new byte[len];
            if (in.read(block, 0, len) < len) { throw new IllegalArgumentException("malformed"); }
            blocks.add(block);
        }
        return blocks.toArray(byte[][]::new);
    }

    public static void swap(byte[] bytes, int a, int b) {
        byte tmp = bytes[a];
        bytes[a] = bytes[b];
        bytes[b] = tmp;
    }

    public static byte[] reverse(byte[] data) {
        for (int i = 0; i < data.length/2; ++i) {
            swap(data, i, data.length - i - 1);
        }
        return data;
    }

    public static byte[] secureRandomBytes(int length) {
        return SECURE_RANDOM.generateSeed(length);
    }

    public static BigInteger randomIntegerMod(BigInteger modulus) {
        // Use rejection sampling to eliminate bias. Usually this will only need one iteration, two at a rarity.
        BigInteger val = modulus;
        while (val.compareTo(modulus) >= 0) {
            val = new BigInteger(modulus.bitLength(), SECURE_RANDOM);
        }
        return val;
    }

    public static byte[] unsignedBytes(BigInteger i) {
        var bytes = i.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }
}
