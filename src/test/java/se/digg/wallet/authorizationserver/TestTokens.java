// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/** Builds device keys, device-key assertions and DPoP proofs for tests. */
public final class TestTokens {

  public static final String CLIENT_ID = "wallet-app";

  private TestTokens() {}

  public static ECKey newDeviceKey() throws JOSEException {
    return new ECKeyGenerator(Curve.P_256).generate();
  }

  public static JWTClaimsSet.Builder assertionClaims(String serverIssuer) {
    Instant now = Instant.now();
    return new JWTClaimsSet.Builder()
        .issuer(CLIENT_ID)
        .subject(CLIENT_ID)
        .audience(serverIssuer)
        .issueTime(Date.from(now))
        .expirationTime(Date.from(now.plusSeconds(60)))
        .jwtID(UUID.randomUUID().toString());
  }

  /** An assertion signed by the device key, with its public key in the {@code jwk} header. */
  public static String assertion(ECKey deviceKey, JWTClaimsSet claims) throws JOSEException {
    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
        .type(JOSEObjectType.JWT)
        .jwk(deviceKey.toPublicJWK())
        .build();
    return sign(header, claims, deviceKey);
  }

  public static String assertion(ECKey deviceKey, String serverIssuer) throws JOSEException {
    return assertion(deviceKey, assertionClaims(serverIssuer).build());
  }

  public static String dpopProof(ECKey key, String tokenUri) throws JOSEException {
    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
        .type(new JOSEObjectType("dpop+jwt"))
        .jwk(key.toPublicJWK())
        .build();
    JWTClaimsSet claims = new JWTClaimsSet.Builder()
        .claim("htm", "POST")
        .claim("htu", tokenUri)
        .issueTime(new Date())
        .jwtID(UUID.randomUUID().toString())
        .build();
    return sign(header, claims, key);
  }

  public static String sign(JWSHeader header, JWTClaimsSet claims, ECKey key)
      throws JOSEException {
    SignedJWT jwt = new SignedJWT(header, claims);
    jwt.sign(new ECDSASigner(key));
    return jwt.serialize();
  }
}
