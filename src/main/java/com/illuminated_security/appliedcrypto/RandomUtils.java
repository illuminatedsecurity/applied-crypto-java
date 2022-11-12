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

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class RandomUtils {

    private static final SecureRandom SECURE_RANDOM;

    static {
        SecureRandom it = null;
        try {
            it = SecureRandom.getInstance("NativePRNGNonBlocking");
        } catch (NoSuchAlgorithmException e) {
            it = new SecureRandom();
        }
        SECURE_RANDOM = it;
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
}
