# Censorscope

Censorscope is a lightweight Linux command-line tool that investigates **why a domain
may be inaccessible from your network**. It runs four independent probes (DNS, TCP,
TLS, HTTP), collects evidence, and produces a cautious, readable assessment of the
possible cause.

Results are **heuristic**. Censorscope never claims to identify the exact source of
a restriction with certainty — it explains what it observed, what that evidence
suggests, and where the uncertainty lies.

## Features

- **DNS probe** — compares the system resolver with Google (`8.8.8.8`) and Cloudflare
  (`1.1.1.1`), detects NXDOMAIN, flags private/loopback/link-local/reserved answers,
  and records per-query timing.
- **TCP probe** — tests connectivity to ports 80 and 443 (success, refusal, timeout,
  unreachable), trying every resolved IPv4 address until one connects.
- **TLS probe** — performs a verified handshake with the real SNI and a comparison
  handshake without SNI; certificate verification stays enabled.
- **HTTP probe** — checks status codes (including 403/404/451/5xx), redirect targets,
  the `Server` header, and a small set of blocking/geo-restriction phrases in at most
  64 KiB of response body.
- **Evidence-based classifier** — combines probe results into one of four verdicts
  with a descriptive confidence level and explicit reasons.
- **Polished terminal output** (Rich) and **machine-readable JSON** for scripts.
- No root, no telemetry, no credential or cookie collection, no shell commands.

## Requirements

- Linux
- Python 3.11 or newer

## Installation

From the project directory:

```bash
pip install .
```

Or with pipx (isolated environment, recommended for CLI tools):

```bash
pipx install .
```

For development:

```bash
pip install -e ".[dev]"
```

## Usage

```bash
# Check a domain
censorscope check example.com

# Machine-readable JSON on stdout (nothing else is printed there)
censorscope check example.com --json

# Custom per-operation timeout in seconds (default: 5)
censorscope check example.com --timeout 10

# Help and version
censorscope --help
censorscope --version
```

### Exit codes

| Code | Meaning                                                        |
|------|----------------------------------------------------------------|
| 0    | No problem detected                                            |
| 1    | Possible problem detected (network interference or service restriction) |
| 2    | Inconclusive, or invalid input (error message on stderr)       |

Color is disabled automatically when output is not a terminal or when `NO_COLOR`
is set.

## Example output

```text
╭───────────────────────────── Censorscope 0.1.0 ──────────────────────────────╮
│ Target: pypi.org                                                             │
╰────────────────────── network reachability diagnostic ───────────────────────╯
Probe   Status  Summary                                                     Time
dns     OK      Consistent public addresses: 151.101.0.223,               232 ms
                151.101.128.223, 151.101.192.223, 151.101.64.223
tcp     OK      Connected on port(s) 80, 443                              306 ms
tls     OK      TLS handshake succeeded (TLSv1.3)                         460 ms
http    OK      HTTP responding (status 200)                              764 ms
╭────────────────────────────────── Verdict ───────────────────────────────────╮
│ No problem detected                                                          │
│ Confidence: high                                                             │
│                                                                              │
│ • DNS answers are consistent and public; TCP, TLS, and HTTP checks all       │
│ passed.                                                                      │
│ • No problem detected does not guarantee the absence of filtering.           │
╰──────────────────────────────────────────────────────────────────────────────╯
Completed in 1.76 s
```

## JSON output

`--json` prints a single valid JSON document to stdout:

```json
{
  "target": "example.com",
  "timestamp": "2026-11-08T12:00:00+00:00",
  "probe_results": [
    {
      "name": "dns",
      "status": "success",
      "summary": "Consistent public addresses: 93.184.216.34",
      "details": {
        "resolvers": {
          "system": {"addresses": ["93.184.216.34"], "duration_ms": 12.3, "error": null},
          "google": {"addresses": ["93.184.216.34"], "duration_ms": 45.1, "error": null, "nxdomain": false},
          "cloudflare": {"addresses": ["93.184.216.34"], "duration_ms": 38.0, "error": null, "nxdomain": false}
        },
        "answers_differ": false,
        "non_public_addresses": {},
        "nxdomain": false,
        "system_failed_public_ok": false
      },
      "duration_ms": 96.2,
      "error": null
    }
  ],
  "verdict": "no_problem_detected",
  "confidence": "high",
  "reasons": ["DNS answers are consistent and public; TCP, TLS, and HTTP checks all passed."],
  "duration_ms": 1760.4
}
```

(The example is abbreviated; the real document contains all four probe results.)

Verdicts: `no_problem_detected`, `possible_network_interference`,
`possible_service_restriction`, `inconclusive`.
Confidence levels (`low`, `medium`, `high`) are descriptive, not statistical
probabilities.

## Project structure

```text
censorscope/
├── pyproject.toml
├── README.md
├── LICENSE
├── .gitignore
├── .github/workflows/ci.yml
├── src/censorscope/
│   ├── __init__.py
│   ├── cli.py           # Typer commands, exit codes
│   ├── models.py        # ProbeResult / DiagnosticReport dataclasses
│   ├── validation.py    # domain input validation
│   ├── diagnostics.py   # orchestrator: runs probes, builds the report
│   ├── classifier.py    # rule-based evidence classification
│   ├── reporter.py      # Rich terminal output, JSON serialization
│   └── probes/
│       ├── dns.py
│       ├── tcp.py
│       ├── tls.py
│       └── http.py
└── tests/               # pytest suite, fully mocked (no internet needed)
```

## Running tests

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

The test suite uses mocks (`httpx.MockTransport`, monkeypatched sockets/resolvers)
and does not depend on the public internet.

## Design notes

- The DNS probe runs first; later probes reuse its answers (system resolver
  preferred, public resolvers as fallback). This avoids repeated slow system
  lookups on broken networks and lets the tool test the real service even when
  the system resolver is being manipulated. TLS SNI and certificate verification,
  and the HTTP Host header, always use the real domain.
- The system resolver (`getaddrinfo`) has no timeout parameter and cannot be
  cancelled, so it runs in a daemon thread with a bounded wait. On timeout the
  lookup is reported as failed and the abandoned thread exits with the process.
  This preserves exact system semantics (hosts file, nsswitch) while honoring
  `--timeout`.
- HTTP redirects are recorded but not followed, keeping the probe bounded.
- HTTP proxy environment variables are ignored (`trust_env=False`) so results
  reflect the direct network path.

## Known limitations

- **Heuristic, not proof.** DNS differences, SNI-specific failures, and block-page
  phrases are signals, not certainty. CDNs, geo-DNS, split-horizon DNS, and service
  outages can produce similar patterns. Every verdict includes its reasoning and
  limitations.
- **HTTP restriction signals are capped at medium confidence.** A 451 response or
  a 403 with regional language suggests a service-side restriction, but a CDN,
  proxy, or other network intermediary could generate the same response; the
  origin cannot be verified from the client.
- **Phrase detection is a weak heuristic.** The HTTP probe looks for a small set
  of fixed English phrases in at most the first 64 KiB of each response body. It
  misses block pages in other languages and pages rendered by JavaScript, and
  normal pages can contain such phrases. Phrase hits alone therefore never
  produce a restriction verdict — they are reported as inconclusive unless
  corroborated by a status code such as 403 or 451.
- **IPv4 focus.** Probes compare A records and connect over IPv4; IPv6-only domains
  are not fully diagnosed in this version.
- **No SNI-less certificate hostname matching.** The comparison handshake keeps
  chain verification but relaxes hostname matching (many servers present a default
  certificate without SNI).
- **Linux only** for now; the code is kept portable so Windows support can be added
  later.
- The TCP probe tries every resolved address per port, but TLS and HTTP connection
  attempts use only the first address.
- The HTTP probe does not execute JavaScript or render pages.

## License

MIT — see [LICENSE](LICENSE).