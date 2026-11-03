// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static se.digg.wallet.authorizationserver.domain.DeviceKeyAssertionTestBuilder.CLIENT_ID;
import static se.digg.wallet.authorizationserver.domain.DeviceKeyAssertionTestBuilder.DEVICE_KEY_THUMBPRINT;
import static se.digg.wallet.authorizationserver.domain.DeviceKeyAssertionTestBuilder.NOW;
import static se.digg.wallet.authorizationserver.domain.DeviceKeyAssertionTestBuilder.SERVER_ISSUER;

import java.time.Clock;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class DeviceKeySignInTest {

  private static final DeviceKey ACTIVE_DEVICE_KEY =
      new DeviceKey(DEVICE_KEY_THUMBPRINT, UUID.randomUUID(), DeviceKey.Status.ACTIVE);

  @Mock
  DeviceKeyCredentials deviceKeyCredentials;

  @Mock
  AttestationVerifier attestationVerifier;

  @Mock
  ReplayCache replayCache;

  private DeviceKeySignIn deviceKeySignIn;

  @BeforeEach
  void setUp() {
    deviceKeySignIn = new DeviceKeySignIn(deviceKeyCredentials, attestationVerifier, replayCache,
        Clock.fixed(NOW, ZoneOffset.UTC));
  }

  @Test
  void a_trusted_active_device_key_signs_in_to_its_account() {
    var assertion = DeviceKeyAssertionTestBuilder.withDefaults().build();
    when(attestationVerifier.isTrusted(assertion)).thenReturn(true);
    when(deviceKeyCredentials.findByThumbprint(DEVICE_KEY_THUMBPRINT))
        .thenReturn(Optional.of(ACTIVE_DEVICE_KEY));
    when(replayCache.markUsed("assertion-id", assertion.replayableUntil())).thenReturn(true);

    var deviceKey =
        deviceKeySignIn.signIn(assertion, DEVICE_KEY_THUMBPRINT, CLIENT_ID, SERVER_ISSUER);

    assertThat(deviceKey).isEqualTo(ACTIVE_DEVICE_KEY);
  }

  @Test
  void an_invalid_assertion_is_rejected_without_looking_up_the_device_key() {
    var assertion = DeviceKeyAssertionTestBuilder.withDefaults().issuer("other-app").build();

    assertThatThrownBy(() -> deviceKeySignIn.signIn(assertion, DEVICE_KEY_THUMBPRINT, CLIENT_ID,
        SERVER_ISSUER)).isInstanceOf(SignInRejectedException.class);

    verify(deviceKeyCredentials, never()).findByThumbprint(anyString());
  }

  @Test
  void a_dpop_proof_signed_by_another_key_is_rejected() {
    var assertion = DeviceKeyAssertionTestBuilder.withDefaults().build();

    assertThatThrownBy(
        () -> deviceKeySignIn.signIn(assertion, "other-key", CLIENT_ID, SERVER_ISSUER))
        .isInstanceOf(SignInRejectedException.class)
        .hasMessage("DPoP key does not match the assertion key");
  }

  @Test
  void an_untrusted_device_is_rejected() {
    var assertion = DeviceKeyAssertionTestBuilder.withDefaults().build();
    when(attestationVerifier.isTrusted(assertion)).thenReturn(false);

    assertThatThrownBy(() -> deviceKeySignIn.signIn(assertion, DEVICE_KEY_THUMBPRINT, CLIENT_ID,
        SERVER_ISSUER))
        .isInstanceOf(SignInRejectedException.class)
        .hasMessage("Device or app attestation not trusted");
  }

  @Test
  void an_unregistered_device_key_is_rejected() {
    var assertion = DeviceKeyAssertionTestBuilder.withDefaults().build();
    when(attestationVerifier.isTrusted(assertion)).thenReturn(true);
    when(deviceKeyCredentials.findByThumbprint(DEVICE_KEY_THUMBPRINT))
        .thenReturn(Optional.empty());

    assertThatThrownBy(() -> deviceKeySignIn.signIn(assertion, DEVICE_KEY_THUMBPRINT, CLIENT_ID,
        SERVER_ISSUER))
        .isInstanceOf(SignInRejectedException.class)
        .hasMessage("Unknown or suspended device key");
  }

  @Test
  void a_suspended_device_key_is_rejected() {
    var assertion = DeviceKeyAssertionTestBuilder.withDefaults().build();
    when(attestationVerifier.isTrusted(assertion)).thenReturn(true);
    when(deviceKeyCredentials.findByThumbprint(DEVICE_KEY_THUMBPRINT)).thenReturn(Optional.of(
        new DeviceKey(DEVICE_KEY_THUMBPRINT, UUID.randomUUID(), DeviceKey.Status.SUSPENDED)));

    assertThatThrownBy(() -> deviceKeySignIn.signIn(assertion, DEVICE_KEY_THUMBPRINT, CLIENT_ID,
        SERVER_ISSUER))
        .isInstanceOf(SignInRejectedException.class)
        .hasMessage("Unknown or suspended device key");
  }

  @Test
  void an_already_used_assertion_is_rejected() {
    var assertion = DeviceKeyAssertionTestBuilder.withDefaults().build();
    when(attestationVerifier.isTrusted(assertion)).thenReturn(true);
    when(deviceKeyCredentials.findByThumbprint(DEVICE_KEY_THUMBPRINT))
        .thenReturn(Optional.of(ACTIVE_DEVICE_KEY));
    when(replayCache.markUsed(anyString(), any())).thenReturn(false);

    assertThatThrownBy(() -> deviceKeySignIn.signIn(assertion, DEVICE_KEY_THUMBPRINT, CLIENT_ID,
        SERVER_ISSUER))
        .isInstanceOf(SignInRejectedException.class)
        .hasMessage("Assertion already used");
  }
}
