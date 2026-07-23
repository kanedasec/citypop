# DNS spoofing templates

Create one directory per static template:

```text
templates/dns/my-lab-page/
├── index.html
├── template.json
└── assets/
```

`index.html` is required. `template.json` is optional and controls the selector text:

```json
{
  "name": "My Lab Page",
  "description": "show an authorized security-awareness notice",
  "submission_fields": ["attendance_plan", "activity_choice"]
}
```

The server exposes static files only. Keep asset references relative, for example
`assets/logo.svg`. Template directories containing symbolic links are ignored.

To collect non-sensitive awareness responses, submit a URL-encoded POST form to
`/submit` and declare every accepted field in `submission_fields`. Accepted
responses, HTTP requests, redirects, and DNS events are written to one unified
`dns_spoof_session_*.jsonl` file under the engagement's `DNSSpoof` loot
directory. Undeclared fields and credential-like names are rejected, request
bodies are limited to 8 KiB, and values are limited to 500 characters. Add
`thanks.html` for the post-submission training disclosure page.

Do not use names containing `password`, `token`, `otp`, `pin`, `secret`,
`username`, `email`, payment-card fields, or other authentication data.

When a template is selected, the DNS response address must be an IPv4 address
owned by the City Pop host. The payload—not nginx—temporarily binds an HTTP
redirect server to `0.0.0.0:80` and the HTTPS template server to
`0.0.0.0:443`. Port 80 preserves the requested hostname, path, and query while
redirecting to HTTPS on port 443. The template server uses City Pop's
self-signed certificate, so a browser trust warning is expected. Both servers
stop during payload cleanup. Nginx continues serving the management UI
separately on HTTPS port 8080.

Use only domains and content authorized for the engagement. Do not collect real
credentials or personal information.
