// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.infrastructure;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import se.digg.wallet.authorizationserver.domain.AttestationVerifier;
import se.digg.wallet.authorizationserver.domain.DeviceKeyAssertion;

/**
 * Placeholder that trusts every device. NOT PRODUCTION SAFE: replace with real key attestation and
 * app attestation (Play Integrity / App Attest) verification.
 */
@Component
class UnverifiedAttestationVerifier implements AttestationVerifier {

  private static final Logger log = LoggerFactory.getLogger(UnverifiedAttestationVerifier.class);

  UnverifiedAttestationVerifier() {
    log.warn("Attestation is NOT verified: every device is trusted. Not production safe.");
  }

  @Override
  public boolean isTrusted(DeviceKeyAssertion assertion) {
    return true;
  }
}
