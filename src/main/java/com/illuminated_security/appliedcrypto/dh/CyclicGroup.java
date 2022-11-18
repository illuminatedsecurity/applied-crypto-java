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

/**
 * Abstract interface representing a <em>cyclic group</em> from abstract algebra and group theory.
 *
 * @param <T> the type of elements in the group.
 */
public interface CyclicGroup<T> {

    /**
     * The unique identity element of the group.
     *
     * @return the identity element.
     */
    T identityElement();

    /**
     * The binary operation used by the group. This operation must be associative.
     *
     * @return the group operation.
     */
    T groupOperation(T a, T b);

    /**
     * Returns an operation that applies the {@linkplain #groupOperation(Object, Object)} group operation} to an element
     * repeatedly according to the given scalar value. In an <em>additive group</em> (where the operation is thought of
     * as addition), this operation is <em>scalar multiplication.</em> For a <em>multiplicative group</em>, this
     * operation is exponentiation.
     *
     * @return the scalar operation.
     */
    default T scalarOperation(T element, BigInteger scalar) {
        assert scalar.signum() >= 0; // non-negative exponents only
        T extra = identityElement();
        if (scalar.testBit(0)) { // scalar is odd?
            extra = groupOperation(element, extra);
            scalar = scalar.subtract(BigInteger.ONE);
        }
        while (scalar.compareTo(BigInteger.ONE) > 0) {
            element = groupOperation(element, element);
            scalar = scalar.shiftRight(1); // scalar = scalar / 2
        }
        return groupOperation(extra, element);
    }

    /**
     * Computes the inverse of an element in the group. Every element must have an inverse.
     * @param element the element.
     * @return the inverse of the given element.
     */
    T inverse(T element);

    /**
     * Returns the generator of the group.
     * @return
     */
    T generator();
}
