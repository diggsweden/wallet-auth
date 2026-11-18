// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.infrastructure;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import se.digg.wallet.authorizationserver.domain.DeviceKey;

/**
 * Registers the device keys listed by thumbprint in config, so a client can sign in before there is
 * registration. Empty by default; for development and test environments only. The account id is
 * derived from the thumbprint.
 */
@Component
class DevDeviceKeys {

  private static final Logger logger = LoggerFactory.getLogger(DevDeviceKeys.class);
  private static final String THUMBPRINTS =
      "${wallet.authorization-server.dev.device-key-thumbprints:}";

  DevDeviceKeys(InMemoryDeviceKeyCredentials credentials,
      @Value(THUMBPRINTS) List<String> thumbprints) {
    for (String thumbprint : thumbprints) {
      UUID accountId = UUID.nameUUIDFromBytes(thumbprint.getBytes(StandardCharsets.UTF_8));
      credentials.add(new DeviceKey(thumbprint, accountId, DeviceKey.Status.ACTIVE));
      logger.warn("Registered dev device key {} for account {}", thumbprint, accountId);
    }
  }
}
