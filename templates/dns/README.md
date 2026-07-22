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
responses are written to `awareness_responses_*.jsonl`. Undeclared fields and
credential-like names are rejected, request bodies are limited to 8 KiB, and
values are limited to 500 characters. Add `thanks.html` for the post-submission
training disclosure page.

Do not use names containing `password`, `token`, `otp`, `pin`, `secret`,
`username`, `email`, payment-card fields, or other authentication data.

When a template is selected, the DNS response address must be an IPv4 address
owned by the City Pop host. The payload binds its managed HTTP server to port 80,
logs requests under the engagement's `DNSSpoof` loot directory, and stops the
server during payload cleanup.

Use only domains and content authorized for the engagement. Do not collect real
credentials or personal information.
