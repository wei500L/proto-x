# PROTO-X research workspace

- The user authorizes development, measurement and deployment on the dedicated test VPS only. Preserve its SSH management channel. Do not change the production server.
- Keep credentials, generated certificates/private keys, authenticated configs, SSH state and identifying deployment inventory in `.local/` (ignored by Git). Never print credentials in logs or reports.
- Clearly distinguish real measurements, controlled emulation, simulation and hypotheses. Preserve failures and denominators; never claim an unrun test passed.
- Prefer standard cryptography and reviewed transport implementations. Document delivery and recovery semantics precisely.
- Coordinate shared files. Only the primary agent operates the VPS or changes shared module dependencies. Delegate work in separate directories when useful.
- Keep runnable commands and dated research state so work can continue across sessions. Do not use actual server addresses in public examples.

