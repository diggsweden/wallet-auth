// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureRestTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.client.EntityExchangeResult;
import org.springframework.test.web.servlet.client.RestTestClient;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import se.digg.wallet.authorizationserver.domain.DeviceKey;
import se.digg.wallet.authorizationserver.infrastructure.InMemoryDeviceKeyCredentials;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureRestTestClient
class DeviceKeyTokenComponentTest {

  private static final String JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
  private static final String CLIENT_ID = TestTokens.CLIENT_ID;

  @LocalServerPort
  int port;

  @Autowired
  RestTestClient restClient;

  @Autowired
  InMemoryDeviceKeyCredentials deviceKeys;

  @Nested
  class A_token_issued_to_an_active_device_key {

    private final UUID accountId = UUID.randomUUID();
    private ECKey deviceKey;
    private Map<String, Object> response;
    private SignedJWT accessToken;

    @BeforeEach
    void signIn() throws Exception {
      deviceKey = TestTokens.newDeviceKey();
      register(deviceKey, accountId, DeviceKey.Status.ACTIVE);
      response = requestToken(TestTokens.assertion(deviceKey, issuer()),
          TestTokens.dpopProof(deviceKey, tokenUri()), CLIENT_ID).getResponseBody();
      accessToken = SignedJWT.parse((String) response.get("access_token"));
    }

    @Test
    void is_a_dpop_token() {
      assertThat(response).containsEntry("token_type", "DPoP");
    }

    @Test
    void grants_the_wallet_scope() {
      assertThat(response).containsEntry("scope", "wallet");
    }

    @Test
    void comes_without_a_refresh_token() {
      assertThat(response).doesNotContainKey("refresh_token");
    }

    @Test
    void is_signed_by_the_published_signing_key() throws Exception {
      String jwks = restClient.get().uri("/oauth2/jwks").exchange()
          .returnResult(String.class).getResponseBody();
      ECKey signingKey = JWKSet.parse(jwks).getKeys().getFirst().toECKey();

      assertThat(accessToken.verify(new ECDSAVerifier(signingKey))).isTrue();
    }

    @Test
    void is_bound_to_the_device_key() throws Exception {
      Map<String, Object> cnf = accessToken.getJWTClaimsSet().getJSONObjectClaim("cnf");

      assertThat(cnf).containsEntry("jkt", deviceKey.computeThumbprint().toString());
    }

    @Test
    void names_the_account_as_subject() throws Exception {
      assertThat(accessToken.getJWTClaimsSet().getSubject()).isEqualTo(accountId.toString());
    }

    @Test
    void names_no_wallet() throws Exception {
      assertThat(accessToken.getJWTClaimsSet().getClaims()).doesNotContainKey("wallet_id");
    }

    @Test
    void names_this_server_as_issuer() throws Exception {
      assertThat(accessToken.getJWTClaimsSet().getIssuer()).isEqualTo(issuer());
    }
  }

  @Test
  void an_unregistered_device_key_is_rejected_as_an_invalid_grant() throws Exception {
    ECKey deviceKey = TestTokens.newDeviceKey();

    var result = requestToken(deviceKey);

    assertError(result, 400, "invalid_grant");
  }

  @Test
  void a_suspended_device_key_is_rejected_as_an_invalid_grant() throws Exception {
    ECKey deviceKey = TestTokens.newDeviceKey();
    register(deviceKey, UUID.randomUUID(), DeviceKey.Status.SUSPENDED);

    var result = requestToken(deviceKey);

    assertError(result, 400, "invalid_grant");
  }

  @Test
  void a_request_without_a_dpop_proof_is_rejected() throws Exception {
    ECKey deviceKey = TestTokens.newDeviceKey();

    var result = requestToken(TestTokens.assertion(deviceKey, issuer()), null, CLIENT_ID);

    assertError(result, 400, "invalid_dpop_proof");
  }

  @Test
  void a_request_with_a_malformed_dpop_proof_is_rejected() throws Exception {
    ECKey deviceKey = TestTokens.newDeviceKey();

    var result = requestToken(TestTokens.assertion(deviceKey, issuer()), "not-a-jwt", CLIENT_ID);

    assertError(result, 400, "invalid_dpop_proof");
  }

  @Test
  void a_dpop_proof_signed_by_another_key_is_rejected_as_an_invalid_grant() throws Exception {
    ECKey deviceKey = TestTokens.newDeviceKey();
    ECKey otherKey = TestTokens.newDeviceKey();

    var result = requestToken(TestTokens.assertion(deviceKey, issuer()),
        TestTokens.dpopProof(otherKey, tokenUri()), CLIENT_ID);

    assertError(result, 400, "invalid_grant");
  }

  @Test
  void an_expired_assertion_is_rejected_as_an_invalid_grant() throws Exception {
    ECKey deviceKey = TestTokens.newDeviceKey();
    Instant past = Instant.now().minusSeconds(600);
    String assertion = TestTokens.assertion(deviceKey, TestTokens.assertionClaims(issuer())
        .issueTime(Date.from(past))
        .expirationTime(Date.from(past.plusSeconds(60)))
        .build());

    var result =
        requestToken(assertion, TestTokens.dpopProof(deviceKey, tokenUri()), CLIENT_ID);

    assertError(result, 400, "invalid_grant");
  }

  @Test
  void a_replayed_assertion_is_rejected_as_an_invalid_grant() throws Exception {
    ECKey deviceKey = TestTokens.newDeviceKey();
    register(deviceKey, UUID.randomUUID(), DeviceKey.Status.ACTIVE);
    String assertion = TestTokens.assertion(deviceKey, issuer());
    requestToken(assertion, TestTokens.dpopProof(deviceKey, tokenUri()), CLIENT_ID);

    var result =
        requestToken(assertion, TestTokens.dpopProof(deviceKey, tokenUri()), CLIENT_ID);

    assertError(result, 400, "invalid_grant");
  }

  @Test
  void a_request_for_another_scope_is_rejected() throws Exception {
    ECKey deviceKey = TestTokens.newDeviceKey();
    MultiValueMap<String, String> form = tokenForm(TestTokens.assertion(deviceKey, issuer()),
        CLIENT_ID);
    form.add("scope", "account:delete");

    var result = postToken(form, TestTokens.dpopProof(deviceKey, tokenUri()));

    assertError(result, 400, "invalid_scope");
  }

  @Test
  void an_unknown_client_is_rejected() throws Exception {
    ECKey deviceKey = TestTokens.newDeviceKey();

    var result = requestToken(TestTokens.assertion(deviceKey, issuer()),
        TestTokens.dpopProof(deviceKey, tokenUri()), "unknown-app");

    assertError(result, 401, "invalid_client");
  }

  private String issuer() {
    return "http://localhost:" + port;
  }

  private String tokenUri() {
    return issuer() + "/oauth2/token";
  }

  private void register(ECKey deviceKey, UUID accountId, DeviceKey.Status status)
      throws Exception {
    deviceKeys.add(new DeviceKey(deviceKey.computeThumbprint().toString(), accountId, status));
  }

  private EntityExchangeResult<Map<String, Object>> requestToken(ECKey deviceKey)
      throws Exception {
    return requestToken(TestTokens.assertion(deviceKey, issuer()),
        TestTokens.dpopProof(deviceKey, tokenUri()), CLIENT_ID);
  }

  private EntityExchangeResult<Map<String, Object>> requestToken(String assertion,
      String dpopProof, String clientId) {
    return postToken(tokenForm(assertion, clientId), dpopProof);
  }

  private static MultiValueMap<String, String> tokenForm(String assertion, String clientId) {
    MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
    form.add("grant_type", JWT_BEARER);
    form.add("client_id", clientId);
    form.add("assertion", assertion);
    return form;
  }

  private EntityExchangeResult<Map<String, Object>> postToken(MultiValueMap<String, String> form,
      String dpopProof) {
    return restClient.post().uri("/oauth2/token")
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .headers(headers -> {
          if (dpopProof != null) {
            headers.add("DPoP", dpopProof);
          }
        })
        .body(form)
        .exchange()
        .returnResult(new ParameterizedTypeReference<>() {});
  }

  private static void assertError(EntityExchangeResult<Map<String, Object>> result, int status,
      String error) {
    assertThat(result.getStatus().value()).isEqualTo(status);
    assertThat(result.getResponseBody()).containsEntry("error", error);
  }
}
