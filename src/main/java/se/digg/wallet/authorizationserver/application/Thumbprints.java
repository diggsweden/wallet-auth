// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.application;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import java.text.ParseException;
import java.util.Map;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

/** RFC 7638 thumbprints, the device key id used in {@code cnf.jkt}. */
final class Thumbprints {

  private Thumbprints() {}

  static String of(JWK key) {
    try {
      return key.computeThumbprint().toString();
    } catch (JOSEException ex) {
      throw invalidKey(ex);
    }
  }

  /** Thumbprint of a JWK given as a JSON object, as in a decoded JWT header. */
  static String of(Object jwkJson) {
    if (!(jwkJson instanceof Map<?, ?> json)) {
      throw invalidKey(null);
    }
    try {
      return of(JWK.parse(stringKeys(json)));
    } catch (ParseException ex) {
      throw invalidKey(ex);
    }
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> stringKeys(Map<?, ?> json) {
    return (Map<String, Object>) json;
  }

  private static OAuth2AuthenticationException invalidKey(Throwable cause) {
    OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "Invalid key", null);
    return cause == null ? new OAuth2AuthenticationException(error)
        : new OAuth2AuthenticationException(error, cause);
  }
}
