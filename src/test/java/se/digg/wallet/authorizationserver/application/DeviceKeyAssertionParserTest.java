// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import se.digg.wallet.authorizationserver.TestTokens;

class DeviceKeyAssertionParserTest {

  private static final String SERVER_ISSUER = "https://as.example";

  @Test
  void an_assertion_signed_by_its_header_key_is_read_with_that_key_thumbprint() throws Exception {
    ECKey deviceKey = TestTokens.newDeviceKey();
    String value = TestTokens.assertion(deviceKey, SERVER_ISSUER);

    var assertion = DeviceKeyAssertionParser.parse(value);

    assertThat(assertion.deviceKeyThumbprint())
        .isEqualTo(deviceKey.computeThumbprint().toString());
  }

  @Test
  void an_assertion_signed_by_another_key_than_its_header_key_is_rejected() throws Exception {
    ECKey deviceKey = TestTokens.newDeviceKey();
    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
        .jwk(deviceKey.toPublicJWK())
        .build();
    String value = TestTokens.sign(header, TestTokens.assertionClaims(SERVER_ISSUER).build(),
        TestTokens.newDeviceKey());

    assertThatThrownBy(() -> DeviceKeyAssertionParser.parse(value))
        .isInstanceOfSatisfying(OAuth2AuthenticationException.class, ex -> assertThat(
            ex.getError().getDescription()).isEqualTo("Invalid assertion signature"));
  }

  @Test
  void an_assertion_with_a_private_key_in_its_header_is_rejected() throws Exception {
    ECKey deviceKey = TestTokens.newDeviceKey();
    String signed = TestTokens.assertion(deviceKey, SERVER_ISSUER);
    String header = Base64URL.encode("""
        {"alg":"ES256","jwk":%s}""".formatted(deviceKey.toJSONString())).toString();
    String value = header + signed.substring(signed.indexOf('.'));

    assertThatThrownBy(() -> DeviceKeyAssertionParser.parse(value))
        .isInstanceOfSatisfying(OAuth2AuthenticationException.class, ex -> assertThat(
            ex.getError().getDescription()).isEqualTo("Assertion is not a signed JWT"));
  }

  @Test
  void an_assertion_signed_with_es384_is_rejected() throws Exception {
    ECKey p384Key = new ECKeyGenerator(Curve.P_384).generate();
    JWSHeader header =
        new JWSHeader.Builder(JWSAlgorithm.ES384).jwk(p384Key.toPublicJWK()).build();
    String value =
        TestTokens.sign(header, TestTokens.assertionClaims(SERVER_ISSUER).build(), p384Key);

    assertThatThrownBy(() -> DeviceKeyAssertionParser.parse(value))
        .isInstanceOfSatisfying(OAuth2AuthenticationException.class,
            ex -> assertThat(ex.getError().getDescription())
                .isEqualTo("Assertion must be signed with ES256 by the P-256 key in its header"));
  }

  @Test
  void an_assertion_without_a_key_in_its_header_is_rejected() throws Exception {
    ECKey deviceKey = TestTokens.newDeviceKey();
    String value = TestTokens.sign(new JWSHeader(JWSAlgorithm.ES256),
        TestTokens.assertionClaims(SERVER_ISSUER).build(), deviceKey);

    assertThatThrownBy(() -> DeviceKeyAssertionParser.parse(value))
        .isInstanceOfSatisfying(OAuth2AuthenticationException.class,
            ex -> assertThat(ex.getError().getDescription())
                .isEqualTo("Assertion must be signed with ES256 by the P-256 key in its header"));
  }

  @Test
  void a_value_that_is_not_a_jwt_is_rejected() {
    assertThatThrownBy(() -> DeviceKeyAssertionParser.parse("not-a-jwt"))
        .isInstanceOfSatisfying(OAuth2AuthenticationException.class, ex -> assertThat(
            ex.getError().getDescription()).isEqualTo("Assertion is not a signed JWT"));
  }
}
