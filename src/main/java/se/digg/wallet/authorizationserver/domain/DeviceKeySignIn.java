// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.domain;

import java.time.Clock;

/**
 * Signs in a device with its device key: the key must have signed a valid assertion and the DPoP
 * proof, come from a trusted device and be an active sign-in method of an account. Each assertion
 * works once.
 */
public class DeviceKeySignIn {

  private final DeviceKeyCredentials deviceKeyCredentials;
  private final AttestationVerifier attestationVerifier;
  private final ReplayCache replayCache;
  private final Clock clock;

  public DeviceKeySignIn(DeviceKeyCredentials deviceKeyCredentials,
      AttestationVerifier attestationVerifier, ReplayCache replayCache, Clock clock) {
    this.deviceKeyCredentials = deviceKeyCredentials;
    this.attestationVerifier = attestationVerifier;
    this.replayCache = replayCache;
    this.clock = clock;
  }

  /**
   * Returns the signed-in device key and the account it belongs to.
   *
   * @throws SignInRejectedException if the device may not sign in
   */
  public DeviceKey signIn(DeviceKeyAssertion assertion, String dpopKeyThumbprint, String clientId,
      String serverIssuer) {
    assertion.requireValid(clientId, serverIssuer, clock.instant());
    requireSameKey(assertion, dpopKeyThumbprint);
    requireTrustedDevice(assertion);
    DeviceKey deviceKey = findActiveDeviceKey(assertion.deviceKeyThumbprint());
    requireFirstUse(assertion);
    return deviceKey;
  }

  private static void requireSameKey(DeviceKeyAssertion assertion, String dpopKeyThumbprint) {
    if (!assertion.deviceKeyThumbprint().equals(dpopKeyThumbprint)) {
      throw new SignInRejectedException("DPoP key does not match the assertion key");
    }
  }

  private void requireTrustedDevice(DeviceKeyAssertion assertion) {
    if (!attestationVerifier.isTrusted(assertion)) {
      throw new SignInRejectedException("Device or app attestation not trusted");
    }
  }

  private DeviceKey findActiveDeviceKey(String deviceKeyThumbprint) {
    return deviceKeyCredentials.findByThumbprint(deviceKeyThumbprint)
        .filter(DeviceKey::isActive)
        .orElseThrow(() -> new SignInRejectedException("Unknown or suspended device key"));
  }

  private void requireFirstUse(DeviceKeyAssertion assertion) {
    if (!replayCache.markUsed(assertion.id(), assertion.replayableUntil())) {
      throw new SignInRejectedException("Assertion already used");
    }
  }
}
