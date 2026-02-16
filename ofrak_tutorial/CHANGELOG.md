# Changelog
All notable changes to `ofrak-tutorial` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased: 0.1.2](https://github.com/redballoonsecurity/ofrak/tree/master)
### Changed
- Remove test dependencies that are already in the global `requirements-dev.txt` ([#695](https://github.com/redballoonsecurity/ofrak/pull/695))
- Remove `pkg_resources` usage from `setup.py`, broken by setuptools 82.0.0; inline dependencies directly ([#708](https://github.com/redballoonsecurity/ofrak/pull/708))

### Fixed
- Update Notebook 3 output to make testing on different configurations easier ([#593](https://github.com/redballoonsecurity/ofrak/pull/593))

## 0.1.0
### Added
Initial release. Hello world!
