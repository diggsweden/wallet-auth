// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.application;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.Set;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

/**
 * Reads a jwt-bearer token request and its DPoP header into a
 * {@link DeviceKeyGrantAuthenticationToken}.
 */
public class DeviceKeyGrantAuthenticationConverter implements AuthenticationConverter {

  @Override
  public Authentication convert(HttpServletRequest request) {
    if (!AuthorizationGrantType.JWT_BEARER.getValue().equals(request.getParameter("grant_type"))) {
      return null;
    }
    String assertion = singleParameter(request, "assertion");
    if (!StringUtils.hasText(assertion)) {
      throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }
    String scope = singleParameter(request, "scope");
    Set<String> scopes = StringUtils.hasText(scope)
        ? StringUtils.commaDelimitedListToSet(scope.replace(' ', ','))
        : Set.of();

    if (Collections.list(request.getHeaders("DPoP")).size() > 1) {
      throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }
    Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
    return new DeviceKeyGrantAuthenticationToken(clientPrincipal, assertion, scopes,
        request.getHeader("DPoP"), request.getMethod(), request.getRequestURL().toString());
  }

  private static String singleParameter(HttpServletRequest request, String name) {
    String[] values = request.getParameterValues(name);
    if (values == null) {
      return null;
    }
    if (values.length != 1) {
      throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    }
    return values[0];
  }
}
