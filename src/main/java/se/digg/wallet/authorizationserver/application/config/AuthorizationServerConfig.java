// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.application.config;

import static org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT;
import static org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED;
import static org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT;
import static org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED;
import static org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadataClaimNames.TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS;
import static org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerMetadataEndpointConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2ClientAuthenticationConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import se.digg.wallet.authorizationserver.application.PublicClientAuthentication;

@Configuration
class AuthorizationServerConfig {

  static final String WALLET_APP_CLIENT_ID = "wallet-app";
  static final String WALLET_SCOPE = "wallet";

  private static final Logger log = LoggerFactory.getLogger(AuthorizationServerConfig.class);

  @Bean
  SecurityFilterChain authorizationServerFilterChain(HttpSecurity http,
      RegisteredClientRepository clients, AuthorizationServerSettings settings) {
    http.oauth2AuthorizationServer(server -> server
        .clientAuthentication(clientAuth -> allowPublicClients(clientAuth, clients))
        .authorizationServerMetadataEndpoint(AuthorizationServerConfig::advertiseOnlySupported))
        // Spring cannot switch these endpoints off: tokens are verified against JWKS instead.
        .addFilterBefore(notFound(settings.getTokenRevocationEndpoint(),
            settings.getTokenIntrospectionEndpoint()), SecurityContextHolderFilter.class)
        .authorizeHttpRequests(authorize -> authorize
            .requestMatchers("/actuator/health/**").permitAll()
            .anyRequest().authenticated());
    return http.build();
  }

  private static void allowPublicClients(OAuth2ClientAuthenticationConfigurer clientAuth,
      RegisteredClientRepository clients) {
    clientAuth
        .authenticationConverter(new PublicClientAuthentication.Converter())
        .authenticationProvider(new PublicClientAuthentication.Provider(clients));
  }

  /** Spring's defaults advertise every grant and endpoint; keep only what we support. */
  private static void advertiseOnlySupported(
      OAuth2AuthorizationServerMetadataEndpointConfigurer metadata) {
    metadata.authorizationServerMetadataCustomizer(builder -> builder.claims(claims -> {
      claims.put(TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
          List.of(ClientAuthenticationMethod.NONE.getValue()));
      removeUnsupported(claims);
    }));
  }

  private static void removeUnsupported(Map<String, Object> claims) {
    claims.keySet().removeAll(List.of(REVOCATION_ENDPOINT,
        REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED, INTROSPECTION_ENDPOINT,
        INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED, TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS));
  }

  private static Filter notFound(String... paths) {
    RequestMatcher disabled = new OrRequestMatcher(Arrays.stream(paths)
        .map(path -> (RequestMatcher) PathPatternRequestMatcher.withDefaults().matcher(path))
        .toList());
    return (request, response, chain) -> {
      if (disabled.matches((HttpServletRequest) request)) {
        ((HttpServletResponse) response).setStatus(HttpServletResponse.SC_NOT_FOUND);
        return;
      }
      chain.doFilter(request, response);
    };
  }

  @Bean
  Clock clock() {
    return Clock.systemUTC();
  }

  @Bean
  RegisteredClientRepository registeredClientRepository() {
    RegisteredClient walletApp = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId(WALLET_APP_CLIENT_ID)
        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
        .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
        .scope(WALLET_SCOPE)
        .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(5)).build())
        .build();
    return new InMemoryRegisteredClientRepository(walletApp);
  }

  @Bean
  OAuth2AuthorizationService authorizationService() {
    return new InMemoryOAuth2AuthorizationService();
  }

  @Bean
  JWKSource<SecurityContext> jwkSource(
      @Value("${wallet.authorization-server.signing-key:}") String signingKey)
      throws ParseException, JOSEException {
    ECKey key;
    if (StringUtils.hasText(signingKey)) {
      key = ECKey.parse(signingKey);
    } else {
      log.warn("No signing key configured: generated an ephemeral key. Not for production.");
      key = new ECKeyGenerator(Curve.P_256)
          .keyUse(KeyUse.SIGNATURE)
          .keyID(UUID.randomUUID().toString())
          .generate();
    }
    return new ImmutableJWKSet<>(new JWKSet(key));
  }

  /** Access tokens are signed with the EC signing key (Spring defaults to RS256). */
  @Bean
  OAuth2TokenCustomizer<JwtEncodingContext> es256AccessTokens() {
    return context -> {
      if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
        context.getJwsHeader().algorithm(SignatureAlgorithm.ES256);
      }
    };
  }
}
