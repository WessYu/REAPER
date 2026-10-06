# Contributing

Use Node.js 22 or 24 and `npm ci --ignore-scripts`. Run `npm run check` before proposing changes. Tests use Node's built-in runner; source code is strict TypeScript.

Each detection rule needs both positive and negative fixtures. Include adversarial cases: aliases, shadowed names, helper calls, principal/request confusion and missing schema context. Never suppress a failing test to make CI pass.

A finding must retain real evidence, distinguish inference from runtime confirmation, and document its coverage boundary. Avoid source snippets containing credentials. An unsupported construct should produce a diagnostic when recognized; it must not be silently certified safe.

The PostgreSQL integration suite requires a disposable database and privileges to create synthetic schema objects and roles. CI provisions PostgreSQL 17. REAPER's production introspector must remain catalog-only and read-only.

Keep CLI commands, API exports, rule documentation and fixtures consistent. Do not add placeholder commands or advertise roadmap work as implemented.
