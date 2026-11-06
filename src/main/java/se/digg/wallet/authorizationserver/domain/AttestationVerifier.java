// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.domain;

/**
 * Decides whether a device-key assertion comes from a genuine device and app, based on the key
 * attestation and app attestation it carries.
 */
public interface AttestationVerifier {

  /** Returns true if the assertion's device key and app are trusted. */
  boolean isTrusted(DeviceKeyAssertion assertion);
}
