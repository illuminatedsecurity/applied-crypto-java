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

public class AdditiveIntegerGroup implements CyclicGroup<BigInteger> {
    @Override
    public BigInteger identityElement() {
        return BigInteger.ZERO;
    }

    @Override
    public BigInteger groupOperation(BigInteger x, BigInteger y) {
        return x.add(y);
    }

    @Override
    public BigInteger inverse(BigInteger element) {
        return element.negate();
    }

    @Override
    public BigInteger generator() {
        return BigInteger.ONE;
    }
}
