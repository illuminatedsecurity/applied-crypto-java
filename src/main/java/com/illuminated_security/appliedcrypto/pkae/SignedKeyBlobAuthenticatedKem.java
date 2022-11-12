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

package com.illuminated_security.appliedcrypto.pkae;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Optional;

import javax.crypto.SecretKey;

import com.illuminated_security.appliedcrypto.Utils;
import com.illuminated_security.appliedcrypto.rsa.KeyEncapsulationMechanism;
import com.illuminated_security.appliedcrypto.rsa.KeyEncapsulationMechanism.EncapsulatedKey;
import com.illuminated_security.appliedcrypto.sig.DigitalSignature;

public class SignedKeyBlobAuthenticatedKem implements AuthenticatedKem {

    private final KeyEncapsulationMechanism unauthenticatedKem;
    private final DigitalSignature signature;

    public SignedKeyBlobAuthenticatedKem(KeyEncapsulationMechanism unauthenticatedKem, DigitalSignature signature) {
        this.unauthenticatedKem = unauthenticatedKem;
        this.signature = signature;
    }

    @Override
    public EncapsulatedKey encapsulate(KeyPair senderKeys, PublicKey recipient, byte[] context) {
        // Include our public signature key in the KDF context to prevent signature stripping attacks
        var contextWithPk = Utils.concat(senderKeys.getPublic().getEncoded(), context);
        var encapsulatedKey = unauthenticatedKem.encapsulate(recipient, contextWithPk);
        var keyBlob = encapsulatedKey.getEncapsulation();
        var sig = signature.sign(senderKeys.getPrivate(), keyBlob);
        assert keyBlob.length <= 65535;
        var keyBlobLen = new byte[] { (byte)(keyBlob.length >>> 8 & 0xFF), (byte)(keyBlob.length & 0xFF) };

        return new EncapsulatedKey(encapsulatedKey.getDemKey(), Utils.concat(keyBlobLen, keyBlob, sig));
    }

    @Override
    public Optional<SecretKey> decapsulate(KeyPair recipientKeys, PublicKey sender, byte[] context,
            byte[] encapsulatedKey) {
        assert encapsulatedKey.length > 2;
        var keyBlobLen = (encapsulatedKey[0] & 0xFF) << 8 | (encapsulatedKey[1] & 0xFF);
        var keyBlob = Arrays.copyOfRange(encapsulatedKey, 2, 2 + keyBlobLen);
        var sig = Arrays.copyOfRange(encapsulatedKey, 2 + keyBlobLen, encapsulatedKey.length);

        if (!signature.verify(sender, keyBlob, sig)) {
            return Optional.empty();
        }

        var contextWithPk = Utils.concat(sender.getEncoded(), context);
        return unauthenticatedKem.decapsulate(recipientKeys.getPrivate(), contextWithPk, keyBlob);
    }
}
