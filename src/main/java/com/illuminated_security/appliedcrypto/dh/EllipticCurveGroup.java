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

package com.illuminated_security.appliedcrypto.dh;

import java.math.BigInteger;
import java.security.spec.ECPoint;

public class EllipticCurveGroup implements CyclicGroup<ECPoint> {
    private static final BigInteger P = BigInteger.valueOf(13);
    private static final BigInteger A = BigInteger.valueOf(10);
    @Override
    public ECPoint identityElement() {
        return ECPoint.POINT_INFINITY;
    }

    @Override
    public ECPoint groupOperation(ECPoint a, ECPoint b) {
        return pointAddition(a, b);
    }

    public static ECPoint pointAddition(ECPoint a, ECPoint b) {
        if (a == ECPoint.POINT_INFINITY) { return b; }
        if (b == ECPoint.POINT_INFINITY) { return a; }

        var x1 = a.getAffineX();
        var x2 = b.getAffineX();
        var y1 = a.getAffineY();
        var y2 = b.getAffineY();

        if (x1.equals(x2) && y1.equals(y2.negate().mod(P))) {
            // P = -Q
            return ECPoint.POINT_INFINITY;
        }

        BigInteger delta;
        if (a.equals(b) && !y1.equals(BigInteger.ZERO)) {
            var three = BigInteger.valueOf(3);
            var divisor = BigInteger.TWO.multiply(y1).modInverse(P);
            delta = three.multiply(x1.modPow(BigInteger.TWO, P)).add(A).multiply(divisor).mod(P);
        } else if (!x1.equals(x2)) {
            var diffX = x1.subtract(x2).mod(P);
            var divisor = diffX.modInverse(P);
            delta = y1.subtract(y2).multiply(divisor).mod(P);
        } else {
            throw new IllegalArgumentException("Undefined");
        }

        // x3 = delta^2 - x1 - x2
        var x3 = delta.modPow(BigInteger.TWO, P).subtract(a.getAffineX()).subtract(b.getAffineX())
                .mod(P);
        // y3 = delta(x1 - x3) - y1
        var y3 = delta.multiply(a.getAffineX().subtract(x3)).subtract(a.getAffineY()).mod(P);
        return new ECPoint(x3, y3);
    }

    @Override
    public ECPoint inverse(ECPoint element) {
        return new ECPoint(element.getAffineY(), element.getAffineY().negate().mod(P));
    }

    @Override
    public ECPoint generator() {
        return new ECPoint(BigInteger.valueOf(1), BigInteger.valueOf(1));
    }
}
