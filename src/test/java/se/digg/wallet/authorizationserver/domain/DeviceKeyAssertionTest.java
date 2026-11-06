// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static se.digg.wallet.authorizationserver.domain.DeviceKeyAssertionTestBuilder.CLIENT_ID;
import static se.digg.wallet.authorizationserver.domain.DeviceKeyAssertionTestBuilder.NOW;
import static se.digg.wallet.authorizationserver.domain.DeviceKeyAssertionTestBuilder.SERVER_ISSUER;

import org.junit.jupiter.api.Test;

class DeviceKeyAssertionTest {

  @Test
  void an_assertion_from_the_client_to_this_server_within_its_lifetime_is_valid() {
    var assertion = DeviceKeyAssertionTestBuilder.withDefaults().build();

    assertThatCode(() -> assertion.requireValid(CLIENT_ID, SERVER_ISSUER, NOW))
        .doesNotThrowAnyException();
  }

  @Test
  void an_assertion_issued_by_another_client_is_rejected() {
    var assertion = DeviceKeyAssertionTestBuilder.withDefaults().issuer("other-app").build();

    assertThatThrownBy(() -> assertion.requireValid(CLIENT_ID, SERVER_ISSUER, NOW))
        .isInstanceOf(SignInRejectedException.class)
        .hasMessage("Assertion issuer is not the client");
  }

  @Test
  void an_assertion_for_another_audience_is_rejected() {
    var assertion =
        DeviceKeyAssertionTestBuilder.withDefaults().audience("https://other.example").build();

    assertThatThrownBy(() -> assertion.requireValid(CLIENT_ID, SERVER_ISSUER, NOW))
        .isInstanceOf(SignInRejectedException.class)
        .hasMessage("Assertion audience is not this server");
  }

  @Test
  void an_assertion_without_an_id_is_rejected() {
    var assertion = DeviceKeyAssertionTestBuilder.withDefaults().id(null).build();

    assertThatThrownBy(() -> assertion.requireValid(CLIENT_ID, SERVER_ISSUER, NOW))
        .isInstanceOf(SignInRejectedException.class)
        .hasMessage("Assertion has no id");
  }

  @Test
  void an_assertion_without_an_expiry_time_is_rejected() {
    var assertion = DeviceKeyAssertionTestBuilder.withDefaults().expiresAt(null).build();

    assertThatThrownBy(() -> assertion.requireValid(CLIENT_ID, SERVER_ISSUER, NOW))
        .isInstanceOf(SignInRejectedException.class)
        .hasMessage("Assertion has no issue or expiry time");
  }

  @Test
  void an_assertion_valid_for_longer_than_five_minutes_is_rejected() {
    var assertion = DeviceKeyAssertionTestBuilder.withDefaults()
        .expiresAt(NOW.plusSeconds(5 * 60 + 1))
        .build();

    assertThatThrownBy(() -> assertion.requireValid(CLIENT_ID, SERVER_ISSUER, NOW))
        .isInstanceOf(SignInRejectedException.class)
        .hasMessage("Assertion lifetime is longer than PT5M");
  }

  @Test
  void an_assertion_that_expired_more_than_thirty_seconds_ago_is_rejected() {
    var assertion = DeviceKeyAssertionTestBuilder.withDefaults()
        .issuedAt(NOW.minusSeconds(91))
        .expiresAt(NOW.minusSeconds(31))
        .build();

    assertThatThrownBy(() -> assertion.requireValid(CLIENT_ID, SERVER_ISSUER, NOW))
        .isInstanceOf(SignInRejectedException.class)
        .hasMessage("Assertion has expired");
  }

  @Test
  void an_assertion_that_expired_within_thirty_seconds_is_valid() {
    var assertion = DeviceKeyAssertionTestBuilder.withDefaults()
        .issuedAt(NOW.minusSeconds(90))
        .expiresAt(NOW.minusSeconds(30))
        .build();

    assertThatCode(() -> assertion.requireValid(CLIENT_ID, SERVER_ISSUER, NOW))
        .doesNotThrowAnyException();
  }

  @Test
  void an_assertion_issued_more_than_thirty_seconds_in_the_future_is_rejected() {
    var assertion = DeviceKeyAssertionTestBuilder.withDefaults()
        .issuedAt(NOW.plusSeconds(31))
        .expiresAt(NOW.plusSeconds(91))
        .build();

    assertThatThrownBy(() -> assertion.requireValid(CLIENT_ID, SERVER_ISSUER, NOW))
        .isInstanceOf(SignInRejectedException.class)
        .hasMessage("Assertion is issued in the future");
  }

  @Test
  void an_assertion_id_must_be_remembered_until_thirty_seconds_after_expiry() {
    var assertion = DeviceKeyAssertionTestBuilder.withDefaults().build();

    var replayableUntil = assertion.replayableUntil();

    assertThat(replayableUntil).isEqualTo(NOW.plusSeconds(90));
  }
}
