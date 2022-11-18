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

import static java.nio.charset.StandardCharsets.*;
import static org.assertj.core.api.Assertions.*;
import static org.assertj.core.api.InstanceOfAssertFactories.type;
import static org.assertj.core.api.SoftAssertions.assertSoftly;

import java.math.BigInteger;

import javax.crypto.interfaces.DHKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.assertj.core.api.Condition;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.illuminated_security.appliedcrypto.hash.HKDF;
import com.illuminated_security.appliedcrypto.hash.HMAC;

public class DHKemTest {

    // Here's some I generated earlier...
    private static final BigInteger P = new BigInteger(
            "32674076699056381175195630411642858990067404718543555192046300471606551767103895303377163610678091129" +
                    "797694721658548176581989118535191698541063325781117163114625699376000639448295691219422795590" +
                    "688224175342763662636350555094739649255393680374161313331574205366846854588675028288954199468" +
                    "217857584959786086077201447211293757604308969137952528406096985938120748335279066089878680888" +
                    "773751662397823721193141427423460932207049051244157005003017696541164555696904424859738431808" +
                    "587002712881780967344610661095879310830658351957920313383501723140520564575898998770605754982" +
                    "948731770429327649542547246066569822070919203370178746204939695866726166596027539763137431221" +
                    "436191054174637825314135262782698582116233719802010009823425593781975049826659562291950403730" +
                    "142225416023092258107806904317512319686296916683064572340316314506543269848949108299140283837" +
                    "27971843993092074644891706863735834075831303908623296738155448497027754962902633");
    private static final BigInteger G = new BigInteger(
            "32042378029659843518107194048028018919398458363967002188519169770954593506841911912229461210416572639" +
                    "963535657978721437806857272469130367082194490586114896016715325860552184807245957014425299264" +
                    "947086340412208995678592365544163876051385270259002692843065777623245704297758134572782621901" +
                    "050478435317344955647276398332179742586649879484824408920999433976074239226633013450286470469" +
                    "478875180888135220453343850582959642734699816969707918930984533334040591161350296943353323011" +
                    "206932025173952141318786848481642181827298724345366316428814866693815070675464184698321195210" +
                    "193447506065952086705734720888207782086733734758313420376389756806847121240520874015657282166" +
                    "206270786633523283290441620417645201249673510126467048725067625965038613692752389057696385498" +
                    "930421648843440438843122419042494806558268100185177022963082652475767180973557073540743719124" +
                    "29627300085073853722471668010338412009883529564837931801220025689364475109146186");
    private static final DHParameterSpec PARAMS = new DHParameterSpec(P, G, 3072/2);
    private DHKem kem;

    @BeforeMethod
    public void setup() {
        kem = new DHKem(PARAMS, new HKDF(new HMAC("SHA-512")), "Test".getBytes(UTF_8), "AES");
    }

    @Test
    public void shouldGenerateSecureKeys() {
        System.out.println(System.getProperty("java.vm.version"));
        var keyPair = kem.generateKeyPair();
        assertSoftly(softly -> {
            softly.assertThat(keyPair.getPrivate())
                    .asInstanceOf(type(DHPrivateKey.class))
                    .has(expectedExponentSize())
                    .has(expectedParams());

            var x = ((DHPrivateKey) keyPair.getPrivate()).getX();
            softly.assertThat(keyPair.getPublic())
                    .asInstanceOf(type(DHPublicKey.class))
                    .has(expectedParams())
                    .has(expectedYValue(x));
        });
    }

    @Test
    public void shouldEncryptCorrectly() {
        var keyPair = kem.generateKeyPair();
        var encapKey = kem.encapsulate(keyPair.getPublic(), "Test".getBytes(UTF_8));
        var decapKey =
                kem.decapsulate(keyPair.getPrivate(), "Test".getBytes(UTF_8), encapKey.encapsulation()).orElseThrow();

        assertThat(decapKey).isEqualTo(encapKey.demKey());
    }

    static Condition<DHPrivateKey> expectedExponentSize() {
        return new Condition<>(p -> p.getX().bitLength() == PARAMS.getL(), "Private exponent size");
    }

    static Condition<DHKey> expectedParams() {
        return new Condition<>(k -> equalsConfiguredParams(k.getParams()), "DH parameters");
    }

    static Condition<DHPublicKey> expectedYValue(BigInteger x) {
        return new Condition<>(k -> k.getY().equals(G.modPow(x, P)), "Expected y = g^x (mod p)");
    }

    static boolean equalsConfiguredParams(DHParameterSpec given) {
        return PARAMS.getP().equals(given.getP()) && PARAMS.getG().equals(given.getG()) &&
                (PARAMS.getL() == 0 || PARAMS.getL() == given.getL());
    }
}