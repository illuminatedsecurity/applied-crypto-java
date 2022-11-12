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

package com.illuminated_security.appliedcrypto.ec;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collection;
import java.util.Optional;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.illuminated_security.appliedcrypto.RandomUtils;
import com.illuminated_security.appliedcrypto.ae.KeyWrapCipher;

public class MultiRecipientEcies extends EciesKem implements MultiRecipientKem {
    private final KeyWrapCipher keyWrap;

    public MultiRecipientEcies(String demAlgorithm, KeyWrapCipher keyWrap)
            throws NoSuchAlgorithmException {
        super(demAlgorithm);
        this.keyWrap = keyWrap;
    }

    @Override
    public EncapsulatedKey encapsulate(Collection<PublicKey> publicKeys, byte[] context) {
        var ephemeralKeys = keyPairGenerator.generateKeyPair();
        var demKey = new SecretKeySpec(RandomUtils.secureRandomBytes(32), demAlgorithm);

        var out = new ByteArrayOutputStream();
        var epk = ephemeralKeys.getPublic().getEncoded();
        out.write(epk.length);
        out.writeBytes(epk);
        for (PublicKey recipient : publicKeys) {
            var wrapKey = deriveKey(ephemeralKeys.getPrivate(), recipient,
                    kdfContext(ephemeralKeys.getPublic(), context));
            var wrappedKey = keyWrap.wrap(wrapKey, demKey);
            out.write(wrappedKey.length); // As a single byte
            out.writeBytes(wrappedKey);
        }

        return new EncapsulatedKey(demKey, out.toByteArray());
    }

    @Override
    public Optional<SecretKey> decapsulate(PrivateKey privateKey, byte[] context, byte[] encapsulatedKey) {
        assert encapsulatedKey.length > 0;
        try (var in = new ByteArrayInputStream(encapsulatedKey)) {
            int epkLen = in.read();
            var epkBytes = in.readNBytes(epkLen);
            var epk = keyFactory.generatePublic(new X509EncodedKeySpec(epkBytes));
            var unwrapKey = deriveKey(privateKey, epk, kdfContext(epk, context));

            int wrappedKeyLen;
            while ((wrappedKeyLen = in.read()) != -1) {
                var wrappedKey = in.readNBytes(wrappedKeyLen);
                var demKey = keyWrap.unwrap(unwrapKey, wrappedKey, demAlgorithm);
                if (demKey.isPresent()) {
                    return demKey;
                }
            }
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        } catch (InvalidKeySpecException e) {
            return Optional.empty();
        }
        return Optional.empty();
    }
}
