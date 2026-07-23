# Security Policy

City Pop is a privileged local administration surface for authorized security testing. It is not designed for exposure to the public internet.

## Supported version

Security fixes target the latest revision of the repository’s default branch. Older clones and locally modified installations are not maintained separately.

## Report a vulnerability

Do not open a public issue for authentication bypasses, command injection, path traversal, secret disclosure, unsafe privilege handling, or another vulnerability that could put deployed devices at risk.

Use [GitHub private vulnerability reporting](https://github.com/kanedasec/citypop/security/advisories/new) and include:

- affected revision;
- prerequisites and attack path;
- impact;
- a minimal reproduction using synthetic data;
- suggested mitigation, if known; and
- whether the issue has been disclosed elsewhere.

Never include real session secrets, credentials, captures, personal data, or unauthorized targets. Allow maintainers reasonable time to investigate and release a fix before public disclosure.

## Deployment expectations

- Keep port `8080` on a trusted phone-to-Pi network.
- Use a unique administrator passphrase of at least 15 characters and protect
  `config.json` because it contains the internal session-signing secret.
- Nginx exposes management HTTPS on port `8080` and proxies to Gunicorn on
  loopback port `18080`; do not expose the Gunicorn endpoint.
- Ports `80` and `443` are normally unused by nginx. A DNS-spoof template
  temporarily uses port 80 for HTTP-to-HTTPS redirects and port 443 for its
  self-signed HTTPS site.
- Do not publish the service through router forwarding or public tunnels.
- Change default Kali credentials and keep the Pi-Tail image updated.
- Review payloads and dependencies before using them on real engagements.
- Use a separate assessment adapter so the management route remains recoverable.

Reports about unsupported public-internet deployments, social engineering, or vulnerabilities solely in third-party tools should be directed to the appropriate upstream project unless City Pop introduces the issue.
