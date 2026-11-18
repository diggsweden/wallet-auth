// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.infrastructure;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;
import se.digg.wallet.authorizationserver.domain.DeviceKey;
import se.digg.wallet.authorizationserver.domain.DeviceKeyCredentials;

/** Keeps device keys in memory until the server has a database. Lost on restart. */
@Component
public class InMemoryDeviceKeyCredentials implements DeviceKeyCredentials {

  private final Map<String, DeviceKey> deviceKeys = new ConcurrentHashMap<>();

  /** Adds a device key. Until registration exists, only tests and configured dev keys add keys. */
  public void add(DeviceKey deviceKey) {
    deviceKeys.put(deviceKey.thumbprint(), deviceKey);
  }

  @Override
  public Optional<DeviceKey> findByThumbprint(String thumbprint) {
    return Optional.ofNullable(deviceKeys.get(thumbprint));
  }
}
