# Python SIEM Monitor

A defensive cybersecurity portfolio project for authentication-log analysis, suspicious-activity detection, and incident reporting.

This offline lab processes synthetic authentication events with transparent, configurable rules. It demonstrates entry-level blue-team concepts without connecting to a network or monitoring real people or systems.

## Features

- Parses and validates CSV authentication logs
- Detects repeated failed logins from a source IP
- Flags a successful login after the failure threshold is reached
- Identifies successful logins outside configured business hours
- Flags successful privileged-access events for review
- Assigns rule IDs and severity levels, with evidence and investigation recommendations
- Exports alerts to CSV and JSON and generates a plain-text incident report
- Includes automated unit tests for core rules and report generation
- Uses Python's standard library; no external packages required

## Quick Start

Requires Python 3.10 or later.

From the project root, run:

```bash
python src/siem_monitor.py
```

On Windows, if `python` is not recognized, try:

```bash
py src/siem_monitor.py
```

The default run reads `data/sample_auth_logs.csv` and writes these files into `reports/`:

- `alerts.csv`
- `alerts.json`
- `incident_report.txt`

Run the automated tests from the project root:

```bash
python -m unittest discover -s tests -v
```

## Customize the Run

Choose another input file, output directory, or failed-login threshold:

```bash
python src/siem_monitor.py --input data/sample_auth_logs.csv --output-dir reports --threshold 5
```

The CSV requires `timestamp`, `username`, `source_ip`, `event_type`, and `status` columns. Timestamps use `YYYY-MM-DD HH:MM:SS`. The optional `details` column provides additional context.

## Detection Rules

| Rule ID | Rule | Default severity | Why it matters |
|---|---|---|---|
| `AUTH-001` | Repeated failed logins | High | May indicate password guessing or repeated password-entry mistakes. |
| `AUTH-002` | Success after repeated failures | High | A successful login following repeated failures merits investigation. |
| `AUTH-003` | Login outside configured business hours | Medium | Unusual timing provides context but is not inherently malicious. |
| `PRIV-001` | Privileged access event | Medium | Privileged activity should be checked against authorization and change records. |

Default business hours are 07:00–18:59. The threshold is five failed login events per source IP across the supplied dataset.

These demonstration rules do not yet use a rolling time window, identity correlation, asset context, or allowlists.

## Example Investigation Workflow

1. Run the analyzer and review `reports/alerts.csv`.
2. Select an alert and identify its rule, timestamp, account, source IP, and evidence.
3. Compare it with nearby events in `data/sample_auth_logs.csv`.
4. Write down at least two plausible explanations, including a benign one.
5. Identify additional evidence that would help validate the event, such as identity-provider logs, endpoint telemetry, approved maintenance, or user confirmation.
6. Document a cautious conclusion. An alert is a lead, not proof of compromise.

## Project Structure

```text
python-siem-monitor/
├── README.md
├── LICENSE
├── .gitignore
├── requirements.txt
├── src/
│   ├── siem_monitor.py
│   └── __init__.py
├── data/
│   └── sample_auth_logs.csv
├── tests/
│   └── test_siem_monitor.py
├── reports/
│   ├── alerts.csv
│   ├── alerts.json
│   └── incident_report.txt
└── screenshots/
    ├── automated-tests-passing.png
    ├── incident-report-example.png
    ├── siem-alerts-output.png
    └── siem-detection-results.png
```

## Portfolio Evidence

The screenshots document the local program execution, generated alerts, incident report, and automated tests. The project uses synthetic data only.

Do not upload employer logs, customer information, credentials, private IP inventories, or other sensitive work data. Screenshots should be captured from your own run.

## Limitations and Future Improvements

This is a learning simulation, not a production SIEM. It uses static sample logs, simple per-dataset counts, and hand-written rules. It does not ingest live telemetry, enrich IP addresses, perform automated response, or prove malicious intent.

Potential improvements include rolling-window thresholds, IP/account correlation, configurable YAML rules, structured logging, risk scoring, dashboards, and a documented comparison with a dedicated SIEM lab.

## Ethics and Scope

The included data is fictional and intended for defensive education. Only analyze real logs when you are authorized to access and process them.
