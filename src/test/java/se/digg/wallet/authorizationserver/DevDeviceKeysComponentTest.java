// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureRestTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.client.EntityExchangeResult;
import org.springframework.test.web.servlet.client.RestTestClient;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureRestTestClient
class DevDeviceKeysComponentTest {

  private static final ECKey DEVICE_KEY = newDeviceKey();
  private static final String THUMBPRINT = thumbprint(DEVICE_KEY);

  @LocalServerPort
  int port;

  @Autowired
  RestTestClient restClient;

  @DynamicPropertySource
  static void deviceKeyThumbprints(DynamicPropertyRegistry registry) {
    registry.add("wallet.authorization-server.dev.device-key-thumbprints", () -> THUMBPRINT);
  }

  @Test
  void a_device_key_configured_by_thumbprint_can_sign_in() throws Exception {
    String issuer = "http://localhost:" + port;
    MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
    form.add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
    form.add("client_id", TestTokens.CLIENT_ID);
    form.add("assertion", TestTokens.assertion(DEVICE_KEY, issuer));

    EntityExchangeResult<Map<String, Object>> result = restClient.post().uri("/oauth2/token")
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .header("DPoP", TestTokens.dpopProof(DEVICE_KEY, issuer + "/oauth2/token"))
        .body(form)
        .exchange()
        .returnResult(new ParameterizedTypeReference<>() {});

    assertThat(result.getStatus().value()).isEqualTo(200);
    assertThat(result.getResponseBody()).containsKey("access_token");
  }

  private static ECKey newDeviceKey() {
    try {
      return TestTokens.newDeviceKey();
    } catch (JOSEException ex) {
      throw new IllegalStateException(ex);
    }
  }

  private static String thumbprint(ECKey key) {
    try {
      return key.computeThumbprint().toString();
    } catch (JOSEException ex) {
      throw new IllegalStateException(ex);
    }
  }
}
