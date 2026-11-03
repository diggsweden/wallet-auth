// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.application;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import se.digg.wallet.authorizationserver.domain.DeviceKeyAssertion;

/**
 * Reads a jwt-bearer assertion signed with ES256 by the public P-256 device key in its {@code jwk}
 * header. Checks the signature only; the claims are checked by {@link DeviceKeyAssertion}.
 */
final class DeviceKeyAssertionParser {

  private DeviceKeyAssertionParser() {}

  static DeviceKeyAssertion parse(String value) {
    SignedJWT jwt = parseJwt(value);
    ECKey deviceKey = requireEs256PublicKey(jwt.getHeader());
    requireSignedBy(jwt, deviceKey);
    JWTClaimsSet claims = claims(jwt);
    return new DeviceKeyAssertion(Thumbprints.of(deviceKey), claims.getIssuer(),
        claims.getAudience(), claims.getJWTID(), instant(claims.getIssueTime()),
        instant(claims.getExpirationTime()));
  }

  private static SignedJWT parseJwt(String value) {
    try {
      return SignedJWT.parse(value);
    } catch (ParseException ex) {
      throw invalidGrant("Assertion is not a signed JWT", ex);
    }
  }

  private static ECKey requireEs256PublicKey(JWSHeader header) {
    if (!JWSAlgorithm.ES256.equals(header.getAlgorithm())
        || !(header.getJWK() instanceof ECKey key)
        || !Curve.P_256.equals(key.getCurve())) {
      throw invalidGrant("Assertion must be signed with ES256 by the P-256 key in its header",
          null);
    }
    return key;
  }

  private static void requireSignedBy(SignedJWT jwt, ECKey deviceKey) {
    boolean valid;
    try {
      valid = jwt.verify(new ECDSAVerifier(deviceKey));
    } catch (JOSEException ex) {
      throw invalidGrant("Invalid assertion signature", ex);
    }
    if (!valid) {
      throw invalidGrant("Invalid assertion signature", null);
    }
  }

  private static JWTClaimsSet claims(SignedJWT jwt) {
    try {
      return jwt.getJWTClaimsSet();
    } catch (ParseException ex) {
      throw invalidGrant("Invalid assertion claims", ex);
    }
  }

  private static Instant instant(Date date) {
    return date == null ? null : date.toInstant();
  }

  private static OAuth2AuthenticationException invalidGrant(String description, Throwable cause) {
    OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, description, null);
    return cause == null ? new OAuth2AuthenticationException(error)
        : new OAuth2AuthenticationException(error, cause);
  }
}
