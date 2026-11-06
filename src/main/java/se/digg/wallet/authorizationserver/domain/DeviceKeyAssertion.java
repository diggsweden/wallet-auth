// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.domain;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * The claims of a jwt-bearer assertion whose signature has been verified with the device key in its
 * header.
 */
public record DeviceKeyAssertion(String deviceKeyThumbprint, String issuer, List<String> audience,
    String id, Instant issuedAt, Instant expiresAt) {

  static final Duration CLOCK_SKEW = Duration.ofSeconds(30);
  static final Duration MAX_LIFETIME = Duration.ofMinutes(5);

  public DeviceKeyAssertion {
    audience = audience == null ? List.of() : List.copyOf(audience);
  }

  /** Throws {@link SignInRejectedException} unless the assertion is valid at {@code now}. */
  public void requireValid(String clientId, String serverIssuer, Instant now) {
    requireIssuer(clientId);
    requireAudience(serverIssuer);
    requireId();
    requireLifetime();
    requireNotExpired(now);
    requireNotIssuedInFuture(now);
  }

  /** How long the assertion id must be remembered to stop replays. */
  public Instant replayableUntil() {
    return expiresAt.plus(CLOCK_SKEW);
  }

  private void requireIssuer(String clientId) {
    if (!clientId.equals(issuer)) {
      throw new SignInRejectedException("Assertion issuer is not the client");
    }
  }

  private void requireAudience(String serverIssuer) {
    if (!audience.contains(serverIssuer)) {
      throw new SignInRejectedException("Assertion audience is not this server");
    }
  }

  private void requireId() {
    if (id == null || id.isBlank()) {
      throw new SignInRejectedException("Assertion has no id");
    }
  }

  private void requireLifetime() {
    if (issuedAt == null || expiresAt == null) {
      throw new SignInRejectedException("Assertion has no issue or expiry time");
    }
    if (Duration.between(issuedAt, expiresAt).compareTo(MAX_LIFETIME) > 0) {
      throw new SignInRejectedException("Assertion lifetime is longer than " + MAX_LIFETIME);
    }
  }

  private void requireNotExpired(Instant now) {
    if (expiresAt.isBefore(now.minus(CLOCK_SKEW))) {
      throw new SignInRejectedException("Assertion has expired");
    }
  }

  private void requireNotIssuedInFuture(Instant now) {
    if (issuedAt.isAfter(now.plus(CLOCK_SKEW))) {
      throw new SignInRejectedException("Assertion is issued in the future");
    }
  }
}
