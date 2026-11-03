<!--
SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government

SPDX-License-Identifier: CC0-1.0
-->

# Wallet Authorization Server

[![Version](https://img.shields.io/github/v/tag/diggsweden/wallet-authorization-server?style=for-the-badge&color=green&label=Version)](https://github.com/diggsweden/wallet-authorization-server/tags)
[![REUSE](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.reuse.software%2Fstatus%2Fgithub.com%2Fdiggsweden%2Fwallet-authorization-server&query=status&style=for-the-badge&label=REUSE)](https://api.reuse.software/info/github.com/diggsweden/wallet-authorization-server)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/diggsweden/wallet-authorization-server/badge?style=for-the-badge)](https://scorecard.dev/viewer/?uri=github.com/diggsweden/wallet-authorization-server)
![Standard for Public Code Commitment](https://img.shields.io/badge/Standard%20for%20Public%20Code%20Commitment-green?style=for-the-badge)

**Description**: Authorization server for the European Digital Identity Wallet ecosystem.
It authenticates wallet devices and issues access tokens, in the OAuth 2.0 role of
authorization server.

## Table of Contents

- [Installation and Requirements](#installation-and-requirements)
- [Quick start instructions](#quick-start-instructions)
- [Usage](#usage)
- [Known issues](#known-issues)
- [Roadmap](#roadmap)
- [Support](#support)
- [Contributing](#contributing)
- [License](#license)
- [Maintainers](#maintainers)

## Installation and Requirements

- Java 25

## Quick start instructions

```shell
./mvnw spring-boot:run
```

The server starts on port 9000. Without `SIGNING_KEY` (an EC P-256 private JWK) it generates
an ephemeral signing key.

## Usage

Endpoints:

- `GET /.well-known/oauth-authorization-server` - metadata
- `GET /oauth2/jwks` - public signing keys

Access tokens are ES256 JWTs. There is no sign-in grant yet.

## Known issues

- Authorizations are kept in memory, so the server only works as a single instance and
  forgets everything on restart.

## Roadmap

- **Attestation-based client authentication.** The app is currently a public client
  (`client_id` only, auth method `none`). The goal is
  [OAuth 2.0 Attestation-Based Client Authentication](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/)
  (`OAuth-Client-Attestation` and `OAuth-Client-Attestation-PoP` headers), the same scheme the
  app uses with the Wallet Instance Attestation towards the PID issuer. Spring Authorization
  Server has no built-in support, so it needs a custom client authenticator.
- Sign-in with the device key (`jwt-bearer` plus DPoP), with the key looked up in wallet-account.
- Account registration with spärrkod; real key attestation and app attestation.
- Persistent storage (Postgres) and a shared replay cache.

## Support

If you have questions, concerns, bug reports, etc, please file an issue in this repository's Issue Tracker.

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md).

---

## License

This project is licensed under the European Union Public Licence v. 1.2 (EUPL-1.2) - see the [LICENSE](LICENSE) file for details.

The [CODE_OF_CONDUCT](CODE_OF_CONDUCT.md) is from the [Contributor Covenant](https://www.contributor-covenant.org/) and licensed under CC-BY-4.0.

---

## Maintainers

See [CODEOWNERS](CODEOWNERS).
