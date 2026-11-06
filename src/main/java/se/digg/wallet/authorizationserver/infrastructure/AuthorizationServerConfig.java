// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.infrastructure;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.text.ParseException;
import java.time.Clock;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.StringUtils;

@Configuration
class AuthorizationServerConfig {

  private static final Logger log = LoggerFactory.getLogger(AuthorizationServerConfig.class);

  @Bean
  SecurityFilterChain authorizationServerFilterChain(HttpSecurity http) {
    http.oauth2AuthorizationServer(server -> {
    })
        .authorizeHttpRequests(authorize -> authorize
            .requestMatchers("/actuator/health/**").permitAll()
            .anyRequest().authenticated());
    return http.build();
  }

  /** No clients yet: sign-in grants register their own clients. */
  @Bean
  RegisteredClientRepository registeredClientRepository() {
    return new RegisteredClientRepository() {
      @Override
      public void save(RegisteredClient registeredClient) {
        throw new UnsupportedOperationException("No client registration");
      }

      @Override
      public RegisteredClient findById(String id) {
        return null;
      }

      @Override
      public RegisteredClient findByClientId(String clientId) {
        return null;
      }
    };
  }

  @Bean
  Clock clock() {
    return Clock.systemUTC();
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
