// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureRestTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.test.web.servlet.client.RestTestClient;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureRestTestClient
class MetadataAndJwksComponentTest {

  @LocalServerPort
  int port;

  @Autowired
  RestTestClient restClient;

  @Nested
  class The_metadata {

    private Map<String, Object> metadata;

    @BeforeEach
    void fetch() {
      metadata = getJson("/.well-known/oauth-authorization-server");
    }

    @Test
    void names_this_server_as_issuer() {
      assertThat(metadata).containsEntry("issuer", "http://localhost:" + port);
    }

    @Test
    void points_to_the_token_endpoint() {
      assertThat(metadata).containsEntry("token_endpoint",
          "http://localhost:" + port + "/oauth2/token");
    }

    @Test
    void advertises_only_public_clients() {
      assertThat(metadata).containsEntry("token_endpoint_auth_methods_supported", List.of("none"));
    }

    @Test
    void does_not_advertise_revocation_introspection_or_mtls() {
      assertThat(metadata).doesNotContainKeys("revocation_endpoint",
          "revocation_endpoint_auth_methods_supported", "introspection_endpoint",
          "introspection_endpoint_auth_methods_supported",
          "tls_client_certificate_bound_access_tokens");
    }
  }

  @Test
  void the_revocation_endpoint_does_not_exist() {
    var status =
        restClient.post().uri("/oauth2/revoke?token=x").exchange().returnResult().getStatus();

    assertThat(status.value()).isEqualTo(404);
  }

  @Test
  void the_introspection_endpoint_does_not_exist() {
    var status =
        restClient.post().uri("/oauth2/introspect?token=x").exchange().returnResult().getStatus();

    assertThat(status.value()).isEqualTo(404);
  }

  @Nested
  class The_published_signing_key {

    private Map<String, Object> key;

    @BeforeEach
    void fetch() {
      List<?> keys = (List<?>) getJson("/oauth2/jwks").get("keys");
      key = castMap(keys.getFirst());
    }

    @Test
    void is_an_ec_key() {
      assertThat(key).containsEntry("kty", "EC");
    }

    @Test
    void has_a_key_id() {
      assertThat(key).containsKey("kid");
    }

    @Test
    void does_not_include_the_private_key() {
      assertThat(key).doesNotContainKey("d");
    }
  }

  private Map<String, Object> getJson(String path) {
    return restClient.get().uri(path).exchange()
        .returnResult(new ParameterizedTypeReference<Map<String, Object>>() {})
        .getResponseBody();
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> castMap(Object value) {
    return (Map<String, Object>) value;
  }
}
