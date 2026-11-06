// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.domain;

import java.util.UUID;

/** A device key registered as a sign-in method of an account. */
public record DeviceKey(String thumbprint, UUID accountId, Status status) {

  public boolean isActive() {
    return status == Status.ACTIVE;
  }

  /** Whether the key may sign in. */
  public enum Status {
    ACTIVE,
    SUSPENDED
  }
}
