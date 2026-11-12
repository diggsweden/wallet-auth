// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.infrastructure;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;
import se.digg.wallet.authorizationserver.domain.DeviceKey;

class DevDeviceKeysTest {

  private final InMemoryDeviceKeyCredentials credentials = new InMemoryDeviceKeyCredentials();

  @Test
  void a_configured_thumbprint_is_registered_as_an_active_device_key() {
    new DevDeviceKeys(credentials, List.of("thumbprint"));

    assertThat(credentials.findByThumbprint("thumbprint"))
        .hasValueSatisfying(key -> assertThat(key.status()).isEqualTo(DeviceKey.Status.ACTIVE));
  }

  @Test
  void the_same_thumbprint_gets_the_same_account_after_a_restart() {
    new DevDeviceKeys(credentials, List.of("thumbprint"));
    var restarted = new InMemoryDeviceKeyCredentials();
    new DevDeviceKeys(restarted, List.of("thumbprint"));

    assertThat(restarted.findByThumbprint("thumbprint").map(DeviceKey::accountId))
        .isEqualTo(credentials.findByThumbprint("thumbprint").map(DeviceKey::accountId));
  }
}
