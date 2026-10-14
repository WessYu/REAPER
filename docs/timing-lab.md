# Local timing differential lab

REAPER includes a localhost-only timing differential evidence mode for DVWA-style
training labs. It is intentionally separated from the normal remote attack
engine.

The lab compares a baseline with paired negative and positive controls, repeats
the measurements, uses the median and median absolute deviation (MAD), and only
reports strong evidence when the observed differential is large relative to
both the expected delay and measured jitter.

## Safety boundary

The command accepts only these target hosts:

- `localhost`
- `127.0.0.1`
- `::1`

Any other hostname is rejected before a request is sent. The current preset is
for DVWA with its security level set to `low`.

The DVWA session cookie is read from an environment variable so it does not
appear in the process command line.

## Usage

PowerShell:

```powershell
$env:REAPER_LAB_PHPSESSID = "<your local DVWA session id>"
npx reaper timing-lab http://localhost/dvwa/vulnerabilities/sqli/
```

Bash:

```bash
REAPER_LAB_PHPSESSID="<your local DVWA session id>" \
  npx reaper timing-lab http://localhost/dvwa/vulnerabilities/sqli/
```

JSON output:

```bash
npx reaper timing-lab http://localhost/dvwa/vulnerabilities/sqli/ --format json
```

Optional environment controls:

- `REAPER_LAB_SAMPLES` — samples per baseline/control, default `5`, max `20`.
- `REAPER_LAB_DELAY_MS` — expected delay, default `5000`, max `30000`.
- `REAPER_LAB_TIMEOUT_MS` — request timeout, default expected delay + 5000 ms,
  max `60000`.

## Evidence model

For each experiment REAPER records:

- baseline median;
- negative-control median;
- positive-control median;
- MAD for baseline and negative control;
- timeout/error counts;
- positive-minus-negative delta;
- evidence threshold;
- confidence: `HIGH`, `MEDIUM`, `LOW`, or `INCONCLUSIVE`.

A positive-only timeout pattern can also produce HIGH confidence when at least
60% of positive samples time out while the negative control has no timeouts.

This mode is a lab evidence provider. It does not weaken the authorization,
scope, network, or mutation protections of REAPER's normal attack runner.
