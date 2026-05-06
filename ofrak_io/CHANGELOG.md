# Changelog
All notable changes to `ofrak-io` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased: 1.1.4](https://github.com/redballoonsecurity/ofrak/tree/master)

### Fixed
- Fix `StreamCapture` hanging in Jupyter on ARM by writing the escape sentinel directly to the pipe fd rather than through the Python stream wrapper.

## [1.1.3](https://github.com/redballoonsecurity/ofrak/compare/ofrak-io-v1.1.0...ofrak-type-v1.1.3) - 2025-10-03

### Changed
- Minor update to OFRAK Community License, add OFRAK Pro License ([#478](https://github.com/redballoonsecurity/ofrak/pull/478))

### Fixed
- Fix a bug with asyncio in the BatchManager, when using python 3.13 ([#601](https://github.com/redballoonsecurity/ofrak/pull/601))

## [1.1.0](https://github.com/redballoonsecurity/ofrak/releases/tag/ofrak-io-v1.1.0) - 2023-01-03
### Changed
- Removed reference to obsolete `ofrak_components` from README.md.
- Remove `ofrak-io[test]` reliance on `ofrak`.

## 1.0.0 - 2022-09-02
### Added
Initial release. Hello world!
