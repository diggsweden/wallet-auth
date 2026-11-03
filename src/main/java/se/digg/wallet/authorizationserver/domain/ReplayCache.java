// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.domain;

import java.time.Instant;

/** Remembers used assertion ids so that an assertion can only be used once. */
public interface ReplayCache {

  /** Returns true the first time an id is seen, false if it was already used. */
  boolean markUsed(String id, Instant rememberUntil);
}
