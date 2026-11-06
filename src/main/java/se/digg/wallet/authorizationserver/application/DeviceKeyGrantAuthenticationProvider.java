// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.application;

import java.util.List;
import java.util.Set;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.DPoPProofContext;
import org.springframework.security.oauth2.jwt.DPoPProofJwtDecoderFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import se.digg.wallet.authorizationserver.domain.DeviceKey;
import se.digg.wallet.authorizationserver.domain.DeviceKeyAssertion;
import se.digg.wallet.authorizationserver.domain.DeviceKeySignIn;
import se.digg.wallet.authorizationserver.domain.SignInRejectedException;

/**
 * Handles device-key sign-in on the token endpoint: checks the client and DPoP proof, signs the
 * device in with {@link DeviceKeySignIn} and issues an access token bound to the device key through
 * {@code cnf.jkt}. The token's {@code sub} is the account the device key belongs to.
 */
public class DeviceKeyGrantAuthenticationProvider implements AuthenticationProvider {

  private final OAuth2AuthorizationService authorizationService;
  private final OAuth2TokenGenerator<?> tokenGenerator;
  private final DeviceKeySignIn deviceKeySignIn;
  private final DPoPProofJwtDecoderFactory dpopDecoderFactory = new DPoPProofJwtDecoderFactory();

  public DeviceKeyGrantAuthenticationProvider(OAuth2AuthorizationService authorizationService,
      OAuth2TokenGenerator<?> tokenGenerator, DeviceKeySignIn deviceKeySignIn) {
    this.authorizationService = authorizationService;
    this.tokenGenerator = tokenGenerator;
    this.deviceKeySignIn = deviceKeySignIn;
  }

  @Override
  public Authentication authenticate(Authentication authentication) {
    if (!(authentication instanceof DeviceKeyGrantAuthenticationToken request)) {
      return null;
    }
    OAuth2ClientAuthenticationToken clientPrincipal = authenticatedClient(request);
    RegisteredClient client = registeredClient(clientPrincipal);
    Set<String> scopes = grantedScopes(request, client);
    Jwt dpopProof = verifyDpopProof(request);
    DeviceKeyAssertion assertion = DeviceKeyAssertionParser.parse(request.getAssertion());

    DeviceKey deviceKey = signIn(assertion, dpopProof, client);

    OAuth2AccessToken accessToken =
        issueAccessToken(request, client, deviceKey, scopes, dpopProof);
    return new OAuth2AccessTokenAuthenticationToken(client, clientPrincipal, accessToken);
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return DeviceKeyGrantAuthenticationToken.class.isAssignableFrom(authentication);
  }

  private static OAuth2ClientAuthenticationToken authenticatedClient(
      DeviceKeyGrantAuthenticationToken request) {
    if (request.getPrincipal() instanceof OAuth2ClientAuthenticationToken clientPrincipal
        && clientPrincipal.isAuthenticated()) {
      return clientPrincipal;
    }
    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
  }

  private static RegisteredClient registeredClient(OAuth2ClientAuthenticationToken principal) {
    RegisteredClient client = principal.getRegisteredClient();
    if (client == null) {
      throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }
    if (!client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.JWT_BEARER)) {
      throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
    }
    return client;
  }

  private static Set<String> grantedScopes(DeviceKeyGrantAuthenticationToken request,
      RegisteredClient client) {
    Set<String> scopes = request.getScopes().isEmpty() ? client.getScopes() : request.getScopes();
    if (!client.getScopes().containsAll(scopes)) {
      throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
    }
    return scopes;
  }

  private Jwt verifyDpopProof(DeviceKeyGrantAuthenticationToken request) {
    if (request.getDpopProof() == null) {
      throw error(OAuth2ErrorCodes.INVALID_DPOP_PROOF, "DPoP proof is required");
    }
    DPoPProofContext context = DPoPProofContext.withDPoPProof(request.getDpopProof())
        .method(request.getDpopMethod())
        .targetUri(request.getDpopTargetUri())
        .build();
    try {
      return dpopDecoderFactory.createDecoder(context).decode(request.getDpopProof());
    } catch (RuntimeException ex) {
      throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_DPOP_PROOF),
          ex);
    }
  }

  private DeviceKey signIn(DeviceKeyAssertion assertion, Jwt dpopProof,
      RegisteredClient client) {
    String dpopKeyThumbprint = Thumbprints.of(dpopProof.getHeaders().get("jwk"));
    try {
      return deviceKeySignIn.signIn(assertion, dpopKeyThumbprint, client.getClientId(),
          serverContext().getIssuer());
    } catch (SignInRejectedException ex) {
      throw error(OAuth2ErrorCodes.INVALID_GRANT, ex.getMessage());
    }
  }

  private OAuth2AccessToken issueAccessToken(DeviceKeyGrantAuthenticationToken request,
      RegisteredClient client, DeviceKey deviceKey, Set<String> scopes, Jwt dpopProof) {
    String accountId = deviceKey.accountId().toString();
    Jwt jwt = generateJwt(request, client, accountId, scopes, dpopProof);
    OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.DPOP,
        jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), scopes);
    authorizationService.save(OAuth2Authorization.withRegisteredClient(client)
        .principalName(accountId)
        .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
        .authorizedScopes(scopes)
        .token(accessToken, metadata -> metadata
            .put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, jwt.getClaims()))
        .build());
    return accessToken;
  }

  private Jwt generateJwt(DeviceKeyGrantAuthenticationToken request, RegisteredClient client,
      String accountId, Set<String> scopes, Jwt dpopProof) {
    UsernamePasswordAuthenticationToken device =
        UsernamePasswordAuthenticationToken.authenticated(accountId, null, List.of());
    OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
        .registeredClient(client)
        .principal(device)
        .authorizationServerContext(serverContext())
        .authorizedScopes(scopes)
        .tokenType(OAuth2TokenType.ACCESS_TOKEN)
        .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
        .authorizationGrant(request)
        .put(OAuth2TokenContext.DPOP_PROOF_KEY, dpopProof)
        .build();
    if (tokenGenerator.generate(tokenContext) instanceof Jwt jwt) {
      return jwt;
    }
    throw error(OAuth2ErrorCodes.SERVER_ERROR, "Failed to generate the access token");
  }

  private static AuthorizationServerContext serverContext() {
    AuthorizationServerContext context = AuthorizationServerContextHolder.getContext();
    if (context == null) {
      throw error(OAuth2ErrorCodes.SERVER_ERROR, "No authorization server context");
    }
    return context;
  }

  private static OAuth2AuthenticationException error(String code, String description) {
    return new OAuth2AuthenticationException(new OAuth2Error(code, description, null));
  }
}
