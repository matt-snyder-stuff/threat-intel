# Changelog

All notable changes are documented here. Releases follow Semantic Versioning;
the canonical JSON contract is versioned independently by `schema_version`.

## [1.1.0] - 2026-09-02

### Added

- Runtime-enforced Splunk index, lookback, result-limit, and command policy.
- Count-before-detail execution with structured JSONL query audit records.
- Deterministic RSS, Slack, Splunk, and STIX adapter contract tests.
- Full canonical dataset schema coverage and cross-field invariant checks.

### Changed

- Pipeline publication uses atomic file replacement.
- Publisher reliability is maintained independently from item confidence.
- Containers run as a non-root user with immutable base-image references.

[1.1.0]: https://github.com/matt-snyder-stuff/threat-intel/releases/tag/v1.1.0
