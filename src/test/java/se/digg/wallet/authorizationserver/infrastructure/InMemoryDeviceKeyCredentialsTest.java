// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.infrastructure;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import org.junit.jupiter.api.Test;
import se.digg.wallet.authorizationserver.domain.DeviceKey;

class InMemoryDeviceKeyCredentialsTest {

  private final InMemoryDeviceKeyCredentials credentials = new InMemoryDeviceKeyCredentials();

  @Test
  void an_added_device_key_is_found_by_its_thumbprint() {
    var deviceKey = new DeviceKey("thumbprint", UUID.randomUUID(), DeviceKey.Status.ACTIVE);
    credentials.add(deviceKey);

    var found = credentials.findByThumbprint("thumbprint");

    assertThat(found).contains(deviceKey);
  }

  @Test
  void an_unknown_thumbprint_finds_nothing() {
    var found = credentials.findByThumbprint("unknown");

    assertThat(found).isEmpty();
  }
}
