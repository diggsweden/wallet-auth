// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.application;

import java.util.Map;
import java.util.Set;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

/** Token request for the device-key grant: a device-key signed jwt-bearer assertion plus DPoP. */
public class DeviceKeyGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

  private static final long serialVersionUID = 1L;

  private final String assertion;
  private final Set<String> scopes;
  private final String dpopProof;
  private final String dpopMethod;
  private final String dpopTargetUri;

  public DeviceKeyGrantAuthenticationToken(Authentication clientPrincipal, String assertion,
      Set<String> scopes, String dpopProof, String dpopMethod, String dpopTargetUri) {
    super(AuthorizationGrantType.JWT_BEARER, clientPrincipal, Map.of());
    this.assertion = assertion;
    this.scopes = Set.copyOf(scopes);
    this.dpopProof = dpopProof;
    this.dpopMethod = dpopMethod;
    this.dpopTargetUri = dpopTargetUri;
  }

  public String getAssertion() {
    return assertion;
  }

  public Set<String> getScopes() {
    return scopes;
  }

  /** The DPoP header value, or null if none was sent. */
  public String getDpopProof() {
    return dpopProof;
  }

  public String getDpopMethod() {
    return dpopMethod;
  }

  public String getDpopTargetUri() {
    return dpopTargetUri;
  }
}
