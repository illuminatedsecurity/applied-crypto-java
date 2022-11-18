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

public class CodeWheelGroup implements CyclicGroup<Character> {
    @Override
    public Character identityElement() {
        return 'a';
    }

    @Override
    public Character groupOperation(Character x, Character y) {
        int a = x - 'a';
        int b = y - 'a';
        int c = (a + b) % 26;
        return (char)(c + 'a');
    }

    @Override
    public Character inverse(Character element) {
        return (char) (26 - (element - 'a') + 'a');
    }

    @Override
    public Character generator() {
        return 'b';
    }
}
