# REAPER local timing SQL injection lab

The `timing-sqli` command is a deliberately **localhost-only** lab experiment for a DVWA instance under your control. It is not a remote scanner, a broad SQLi proof of exploitation, or an authorization bypass.

## Run

1. Start your local DVWA environment, sign in, and set DVWA Security to **low**.
2. Set `REAPER_DVWA_PHPSESSID` in your shell to the current session identifier. Never put cookies in source files, CLI arguments, reports, or issue descriptions.
3. Run:

```sh
reaper timing-sqli http://127.0.0.1/dvwa/vulnerabilities/sqli/ --format json --output timing.json
reaper timing-sqli http://127.0.0.1/dvwa/vulnerabilities/sqli/ --format sarif --output timing.sarif --fail-on medium
reaper timing-sqli http://127.0.0.1/dvwa/vulnerabilities/sqli/ --format markdown --output timing.md
```

The default terminal output includes observed medians, median absolute deviation (MAD), positive/negative timing difference, thresholds, timeouts and classification. Set `REAPER_TIMING_SAMPLES` to 3–9 and `REAPER_TIMING_TIMEOUT_MS` to 1000–15000 for the real CLI execution.

## Evidence and safety

- Only `localhost`, `127.0.0.1`, or `::1` are accepted; `localhost` is pinned to `127.0.0.1` before requests, preventing host-file or resolver changes from redirecting traffic outside the loopback interface.
- Embedded credentials, query strings, URL fragments and malformed session values are rejected before traffic.
- Only HTTP(S) GET requests are issued; redirects and non-200 responses are not treated as valid timing measurements.
- Controls alternate negative/positive order, reducing drift bias. Invalid controls, timeouts, HTTP errors and incomplete observations produce inconclusive rather than misleading confirmations.
- Each experiment is bounded by sample and timeout caps. Results are timing evidence, **not proof of data exposure** or proof that SQL injection is exploitable in another security mode.
- SARIF/Markdown output only raises `REAPER-TIMING-001` for supported positive observations; it does not include the PHP session identifier or injected payload strings.
- Recheck findings manually in the authorized lab, and prefer parameterized queries and least-privilege database access for remediation.

## Return codes

Exit `0`: completed without failing the configured gate. Exit `1`: finding reaches `--fail-on`. Exit `2`: invalid configuration or inconclusive timing evidence. A successful command does not certify the application as secure.
