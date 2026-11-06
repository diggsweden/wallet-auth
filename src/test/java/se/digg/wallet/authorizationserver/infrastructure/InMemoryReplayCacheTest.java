// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.infrastructure;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

class InMemoryReplayCacheTest {

  private static final Instant NOW = Instant.parse("2026-11-06T12:00:00Z");

  private final InMemoryReplayCache cache =
      new InMemoryReplayCache(Clock.fixed(NOW, ZoneOffset.UTC));

  @Test
  void an_unused_id_is_accepted() {
    var accepted = cache.markUsed("id", NOW.plusSeconds(60));

    assertThat(accepted).isTrue();
  }

  @Test
  void a_used_id_is_rejected_while_it_is_remembered() {
    cache.markUsed("id", NOW.plusSeconds(60));

    var accepted = cache.markUsed("id", NOW.plusSeconds(60));

    assertThat(accepted).isFalse();
  }

  @Test
  void a_used_id_is_accepted_again_once_it_is_forgotten() {
    cache.markUsed("id", NOW.minusSeconds(1));

    var accepted = cache.markUsed("id", NOW.plusSeconds(60));

    assertThat(accepted).isTrue();
  }
}
