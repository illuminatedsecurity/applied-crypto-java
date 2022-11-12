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

package com.illuminated_security.appliedcrypto.auth;

public interface SigmaProtocol {

    default boolean run(Prover prover, Verifier verifier) {
        var commitment = prover.commit();
        var challenge = verifier.challenge(commitment);
        var response = prover.response(challenge);
        return verifier.accept(response);
    }


    interface Prover {
        byte[] commit();
        byte[] response(byte[] challenge);
    }

    interface Verifier {
        byte[] challenge(byte[] commitment);
        boolean accept(byte[] response);
    }

}
