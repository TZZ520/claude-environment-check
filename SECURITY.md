# Security policy

Do not submit API keys, proxy credentials, unredacted reports, or production probe secrets in public issues.

The probe must terminate TLS directly for ClientHello observation, use a random secret of at least 32 bytes, expose only its authoritative DNS zone, and run with recursion disabled. Stable desktop releases must be signed. Dependency, Go, and npm security checks run in CI.

Report vulnerabilities privately to the repository owner before public disclosure. Replace this paragraph with the final security contact before publishing the repository.

