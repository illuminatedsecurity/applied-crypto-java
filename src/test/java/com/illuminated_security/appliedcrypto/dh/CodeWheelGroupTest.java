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

import java.util.TreeSet;

import org.testng.annotations.Test;

public class CodeWheelGroupTest {

    @Test
    public void testGenerator() {
        var group = new CodeWheelGroup();
        char g = group.generator();
        char x = g;
        var members = new TreeSet<Character>();
        for (int i = 0; i < 26; ++i) {
            members.add(x);
            x = group.groupOperation(x, g);
        }
        assertThat(members).hasSize(26);
        assertThat(members.first()).isEqualTo('a');
        assertThat(members.last()).isEqualTo('z');
    }

    @Test
    public void testInverse() {
        var group = new CodeWheelGroup();
        char zero = group.identityElement();

        for (char c = 'a'; c <= 'z'; c++) {
            char inv = group.inverse(c);
            assertThat(group.groupOperation(c, inv)).isEqualTo(zero);
        }
    }
}