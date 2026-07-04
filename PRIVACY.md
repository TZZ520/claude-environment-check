# Privacy

The desktop app performs diagnostics locally. It does not include analytics or telemetry.

Network checks may send the device's public IP, TLS metadata, HTTP headers required for protocol negotiation, and coarse network location to the configured self-hosted probe or disclosed fallback providers. API keys are sent only to `api.anthropic.com`, are held in process memory for the requested check, and are excluded from reports and logs.

The probe stores session observations in memory for ten minutes by default. Operators should disable access logs containing full IP addresses or configure short retention. Exported reports may contain IP addresses, hostnames, ASN information, and system configuration; users must review them before sharing.

