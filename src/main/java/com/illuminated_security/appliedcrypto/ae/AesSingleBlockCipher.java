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

package com.illuminated_security.appliedcrypto.ae;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Optional;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.illuminated_security.appliedcrypto.Utils;

/**
 * An implementation of a CCA-secure encryption scheme without authentication. This encryption scheme can only
 * encrypt messages that are exactly 16 bytes long.
 */
public class AesSingleBlockCipher implements CcaSecureCipher {
    @Override
    public byte[] encrypt(SecretKey key, byte[] plaintext) {
        var key2 = new SecretKeySpec(Utils.secureRandomBytes(16), "AES");
        byte[] c1 = aes(Cipher.ENCRYPT_MODE, key, key2.getEncoded());
        byte[] c2 = aes(Cipher.ENCRYPT_MODE, key2, plaintext);
        return Utils.concat(c1, c2);
    }

    @Override
    public Optional<byte[]> decrypt(SecretKey key, byte[] ciphertext) {
        assert ciphertext.length == 32;
        var key2Bytes = aes(Cipher.DECRYPT_MODE, key, Arrays.copyOf(ciphertext, 16));
        var key2 = new SecretKeySpec(key2Bytes, "AES");
        return Optional.of(aes(Cipher.DECRYPT_MODE, key2, Arrays.copyOfRange(ciphertext, 16, 32)));
    }

    private byte[] aes(int mode, SecretKey key, byte[] block) {
        assert block.length == 16;
        try {
            var cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(mode, key);
            assert cipher.getIV() == null;
            return cipher.doFinal(block);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvalidKeyException | IllegalBlockSizeException e) {
            throw new IllegalArgumentException(e);
        } catch (BadPaddingException e) {
            throw new AssertionError(e);
        }
    }
}
