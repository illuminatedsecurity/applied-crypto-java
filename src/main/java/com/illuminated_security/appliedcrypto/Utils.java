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

import java.io.ByteArrayOutputStream;

public final class Utils {
    public static byte[] concat(byte[]... values) {
        var out = new ByteArrayOutputStream();
        for (var value : values) {
            out.writeBytes(value);
        }
        return out.toByteArray();
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
}
