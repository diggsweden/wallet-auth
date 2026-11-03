// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.domain;

import java.time.Instant;
import java.util.List;

/** A valid assertion at {@link #NOW} for {@link #CLIENT_ID} and {@link #SERVER_ISSUER}. */
public final class DeviceKeyAssertionTestBuilder {

  public static final Instant NOW = Instant.parse("2026-11-06T12:00:00Z");
  public static final String CLIENT_ID = "wallet-app";
  public static final String SERVER_ISSUER = "https://as.example";
  public static final String DEVICE_KEY_THUMBPRINT = "device-key-thumbprint";

  private String deviceKeyThumbprint = DEVICE_KEY_THUMBPRINT;
  private String issuer = CLIENT_ID;
  private List<String> audience = List.of(SERVER_ISSUER);
  private String id = "assertion-id";
  private Instant issuedAt = NOW;
  private Instant expiresAt = NOW.plusSeconds(60);

  private DeviceKeyAssertionTestBuilder() {}

  public static DeviceKeyAssertionTestBuilder withDefaults() {
    return new DeviceKeyAssertionTestBuilder();
  }

  public DeviceKeyAssertionTestBuilder issuer(String issuer) {
    this.issuer = issuer;
    return this;
  }

  public DeviceKeyAssertionTestBuilder audience(String... audience) {
    this.audience = List.of(audience);
    return this;
  }

  public DeviceKeyAssertionTestBuilder id(String id) {
    this.id = id;
    return this;
  }

  public DeviceKeyAssertionTestBuilder issuedAt(Instant issuedAt) {
    this.issuedAt = issuedAt;
    return this;
  }

  public DeviceKeyAssertionTestBuilder expiresAt(Instant expiresAt) {
    this.expiresAt = expiresAt;
    return this;
  }

  public DeviceKeyAssertion build() {
    return new DeviceKeyAssertion(deviceKeyThumbprint, issuer, audience, id, issuedAt, expiresAt);
  }
}
