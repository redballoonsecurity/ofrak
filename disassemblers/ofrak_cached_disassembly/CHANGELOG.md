# Changelog
All notable changes to `ofrak-cached-disassembly` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased 0.2.0rc1](https://github.com/redballoonsecurity/ofrak/tree/master)

### Fixed
- Pass `usedforsecurity=False` to non-cryptographic `hashlib` calls to prevent failures when Python links against FIPS OpenSSL ([#744](https://github.com/redballoonsecurity/ofrak/pull/744))

## 0.1.0 - 2025-07-25
### Added
Initial release. Hello world!
