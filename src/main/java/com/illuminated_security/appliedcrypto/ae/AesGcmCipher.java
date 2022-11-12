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

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import com.illuminated_security.appliedcrypto.Utils;

public final class AesGcmCipher implements AuthenticatedCipherWithAD {
    @Override
    public byte[] encrypt(SecretKey key, byte[] plaintext, byte[] assocData) {
        try {
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipher.updateAAD(assocData);
            var nonce = cipher.getIV();
            var ciphertext = cipher.doFinal(plaintext);
            return Utils.concat(nonce, ciphertext);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new AssertionError(e);
        }
    }

    @Override
    public Optional<byte[]> decrypt(SecretKey key, byte[] ciphertext, byte[] assocData) {
        try {
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ciphertext, 0, 12));
            cipher.updateAAD(assocData);
            return Optional.of(cipher.doFinal(ciphertext, 16, ciphertext.length - 12));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new UnsupportedOperationException(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (AEADBadTagException e) {
            return Optional.empty();
        } catch (GeneralSecurityException e) {
            // NB: BadPaddingException cannot happen in CTR mode
            throw new AssertionError(e);
        }
    }
}
