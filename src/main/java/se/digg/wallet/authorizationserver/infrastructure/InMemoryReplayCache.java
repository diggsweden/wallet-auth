// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.infrastructure;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;
import se.digg.wallet.authorizationserver.domain.ReplayCache;

/** Keeps used assertion ids in memory, so it only stops replays within a single instance. */
@Component
class InMemoryReplayCache implements ReplayCache {

  private final Map<String, Instant> used = new ConcurrentHashMap<>();
  private final Clock clock;

  InMemoryReplayCache(Clock clock) {
    this.clock = clock;
  }

  @Override
  public boolean markUsed(String id, Instant rememberUntil) {
    Instant now = clock.instant();
    used.values().removeIf(until -> until.isBefore(now));
    return used.putIfAbsent(id, rememberUntil) == null;
  }
}
