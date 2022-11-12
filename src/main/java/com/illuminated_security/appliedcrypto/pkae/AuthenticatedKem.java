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
import java.util.Optional;

import javax.crypto.SecretKey;

import com.illuminated_security.appliedcrypto.rsa.KeyEncapsulationMechanism.EncapsulatedKey;

public interface AuthenticatedKem {
    EncapsulatedKey encapsulate(KeyPair senderKeys, PublicKey recipient, byte[] context);
    Optional<SecretKey> decapsulate(KeyPair recipientKeys, PublicKey sender, byte[] context, byte[] encapsulatedKey);
}
