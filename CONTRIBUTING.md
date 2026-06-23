# Contributing

## Rendering Mode Discipline

Layer 3 static checks use simple mode only: fetched HTML, headers, static text, AXTree-like text extraction, and JSON manifests. Do not add Playwright or screenshots to `src/scanner.js`; if a check needs browser execution, it belongs in Layer 4 missions.

Layer 4 missions may use Playwright for navigation and evidence capture. Routing and extraction should prefer accessible text or deterministic DOM text. Screenshots are proof artifacts, not decision input.

When adding a check, label its mode in the code or test name:

- `static`: HTML/header/manifest/log input only.
- `mission`: browser-backed task execution.
- `evidence`: screenshot, trace, or artifact written after a decision.
