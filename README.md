# Synthetic StackHawk SARIF tutorial test

Intentionally vulnerable Python standard-library fixture, bound only to loopback. No real data, accounts or proprietary source. Do not deploy it publicly.

The manual workflow installs HawkScan 6.6.0 through the official action, scans localhost, validates the genuine SARIF export for publication, and uploads it to GitHub code scanning. Raw scan logs stay on the temporary runner. Authentication and application metadata are temporary encrypted repository secrets. The fixture intentionally reflects query input into HTML.
