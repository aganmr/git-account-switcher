# Changelog

All notable changes to Git Account Switcher are documented here.

## [0.1.1] - 2026-11-01

### Fixed

- Git credential slot and per-account credential entries now store the account's **username and identity** alongside the token — Credential Manager entries are self-describing, and a stale username-less entry can no longer masquerade as "in sync" while git authenticates as a different account

## [0.1.0] - 2026-10-31

### Added

- Initial release
