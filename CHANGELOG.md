# Changelog

All notable changes are documented here. Releases follow Semantic Versioning;
the canonical JSON contract is versioned independently by `schema_version`.

## [1.3.0] - 2026-09-02

### Added

- Credential-free, offline conference quickstart with synthetic threat reports.
- `make demo`, `make quickstart`, and a cross-platform `quickstart.py` runner.
- Committed dashboard preview and repository QR code for attendee handoff.
- CI coverage for the complete sample-to-dashboard workflow.

### Changed

- Onboarding now leads with a deterministic two-minute experience before live integrations.
- Docker and the source CLI include the bundled `sample` adapter.

## [1.2.0] - 2026-09-02

### Added

- Environment-specific operational priority scoring from a validated JSON profile.
- Persistent analyst dispositions, ownership, case links, and notes via review state.
- Enforced TLP publication ceilings with excluded-report accounting.
- Version-controlled Sigma and SPL detection validation.

### Changed

- Newly observed threat actors remain visible after a single report.
- Splunk KV Store ingestion consumes canonical IOC arrays and preserves metadata.
- Splunk agent index defaults now match the shipped environment model.

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
[1.2.0]: https://github.com/matt-snyder-stuff/threat-intel/releases/tag/v1.2.0
[1.3.0]: https://github.com/matt-snyder-stuff/threat-intel/releases/tag/v1.3.0
