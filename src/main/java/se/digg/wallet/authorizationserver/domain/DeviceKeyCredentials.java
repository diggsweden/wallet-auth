// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.domain;

import java.util.Optional;

/** The device keys registered as sign-in methods of accounts. */
public interface DeviceKeyCredentials {

  /** Returns the device key with this RFC 7638 thumbprint, or empty if none is registered. */
  Optional<DeviceKey> findByThumbprint(String thumbprint);
}
