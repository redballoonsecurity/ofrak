# Changelog
All notable changes to `ofrak-binary-ninja` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased 0.1.1](https://github.com/redballoonsecurity/ofrak/tree/master)

### Added
- Add `BinaryNinjaAutoLoadProject` / `BinaryNinjaCustomLoadProject` tags and `BinaryNinjaCustomLoadAnalyzer` for custom binary loading with `ProgramAttributes` metadata ([#701](https://github.com/redballoonsecurity/ofrak/pull/701))

### Changed
- **Breaking:** `BinaryNinjaAnalysisResource` moved from `ofrak_binary_ninja.components.identifiers` to `ofrak_binary_ninja.model` ([#701](https://github.com/redballoonsecurity/ofrak/pull/701))
- **Breaking:** `BinaryNinjaAnalyzer` now targets `BinaryNinjaAutoLoadProject` instead of `BinaryNinjaAnalysisResource`; code that manually tagged resources with `BinaryNinjaAnalysisResource` should use `BinaryNinjaAutoLoadProject` or `BinaryNinjaCustomLoadProject` ([#701](https://github.com/redballoonsecurity/ofrak/pull/701))

## 0.1.0 - 2022-01-25
### Added
Initial release. Hello world!
