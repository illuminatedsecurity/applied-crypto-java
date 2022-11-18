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

import static org.assertj.core.api.Assertions.*;

import java.math.BigInteger;
import java.security.spec.ECPoint;
import java.util.ArrayList;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class EllipticCurveGroupTest {

    @Test
    public void testGenerator() {
        var group = new EllipticCurveGroup();
        var g = group.generator();
        var p = g;
        do {
            System.out.println("P = (" + p.getAffineX() + ", " + p.getAffineY() + ")");
            p = group.groupOperation(p, g);
        } while (p != ECPoint.POINT_INFINITY);

        assertThat(p).isSameAs(ECPoint.POINT_INFINITY);
    }

    @Test
    public void testGroupOrder() {
        var group = new EllipticCurveGroup();
        var g = group.generator();
        // The order of the group is 16, so 16G = O.
        assertThat(group.scalarOperation(g, BigInteger.valueOf(16))).isSameAs(ECPoint.POINT_INFINITY);
    }

    @DataProvider
    public Object[][] allPoints() {
        var cases = new ArrayList<Object[]>(14);
        var group = new EllipticCurveGroup();
        var g = group.generator();
        for (int i = 0; i < 13; ++i) {
            cases.add(new Object[] { group.scalarOperation(g, BigInteger.valueOf(i)) });
        }
        cases.add(new Object[] { ECPoint.POINT_INFINITY });
        return cases.toArray(Object[][]::new);
    }

    @Test(dataProvider = "allPoints")
    public void showAllSubGroups(ECPoint g) {
        var group = new EllipticCurveGroup();
        var p = g;
        System.out.println("G = " + pointToString(g));
        int order = 0;
        while (p != ECPoint.POINT_INFINITY) {
            System.out.println(++order + ": " + pointToString(p));
            p = group.groupOperation(p, g);
        }
        System.out.println(++order + " = O");
        System.out.println("Order: " + order);
        System.out.println("---------");
    }

    private String pointToString(ECPoint p) {
        return p == ECPoint.POINT_INFINITY ? "O" : "(" + p.getAffineX() + ", " + p.getAffineY() + ")";
    }
}