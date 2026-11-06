// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.domain;

/** The device cannot sign in. The message says why and is safe to return to the client. */
public class SignInRejectedException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  public SignInRejectedException(String message) {
    super(message);
  }
}
