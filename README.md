Python SIEM Monitor:
A defensive cybersecurity portfolio project for authentication-log analysis, suspicious-activity detection, and incident reporting.

This offline lab processes synthetic authentication events with transparent, configurable rules. It demonstrates entry-level blue-team concepts without connecting to a network or monitoring real people or systems.

Features
Parses and validates CSV authentication logs
Detects repeated failed logins from a source IP
Flags a successful login after the failure threshold is reached
Identifies successful logins outside configured business hours
Flags successful privileged-access events for review
Assigns rule IDs and severity levels, with evidence and investigation recommendations
Exports alerts to CSV and JSON and generates a plain-text incident report
Includes automated unit tests for core rules and report generation
Uses Python's standard library; no external packages required
Quick start
Requires Python 3.10 or later.

python src/siem_monitor.py
On Windows, if python is not recognized, try:

py src/siem_monitor.py
The default run reads data/sample_auth_logs.csv and writes these files into reports/:

alerts.csv
alerts.json
incident_report.txt
Run the tests from the project root:

python -m unittest discover -s tests -v
Customize the run
Choose another input file, output directory, or failed-login threshold:

python src/siem_monitor.py --input data/sample_auth_logs.csv --output-dir reports --threshold 5
The CSV requires timestamp, username, source_ip, event_type, and status columns. Timestamps use YYYY-MM-DD HH:MM:SS. The optional details column is for context.

Detection rules
Rule ID	Rule	Default severity	Why it matters
AUTH-001	Repeated failed logins	High	May indicate password guessing or a user repeatedly mistyping a password.
AUTH-002	Success after repeated failures	High	A successful login following repeated failures merits investigation.
AUTH-003	Login outside configured business hours	Medium	Unusual timing can provide context, but is not inherently malicious.
PRIV-001	Privileged access event	Medium	Privileged activity should be checked against authorization and change records.
Default business hours are 07:00–18:59. The threshold is five failed login events per source IP across the supplied dataset. These simple demonstration rules do not yet use a rolling time window, identity correlation, asset context, or allowlists.

Example investigation workflow
Run the analyzer and review reports/alerts.csv.
Select an alert and identify its rule, timestamp, account, source IP, and evidence.
Compare it with nearby events in data/sample_auth_logs.csv.
Write down at least two plausible explanations, including a benign one.
State what additional evidence would help validate the event, such as identity-provider logs, endpoint telemetry, approved maintenance, or a user confirmation.
Document a cautious conclusion. An alert is a lead, not proof of compromise.
Project layout
python-siem-monitor/
├── README.md
├── LICENSE
├── .gitignore
├── requirements.txt
├── src/siem_monitor.py
├── data/sample_auth_logs.csv
├── tests/test_siem_monitor.py
├── reports/.gitkeep
└── screenshots/.gitkeep
Portfolio evidence to add
After running the project locally, add genuine screenshots showing:

The program completing successfully in your terminal.
alerts.csv with the generated rules and severities.
incident_report.txt and a short analysis of one alert.
The automated tests passing.
Use synthetic data only. Do not upload employer logs, customer information, credentials, private IP inventories, or other sensitive work data. Screenshots should be captured from your own run rather than fabricated.

Limitations and next steps
This is a learning simulation, not a production SIEM. It uses static sample logs, simple per-dataset counts, and hand-written rules. It does not ingest live telemetry, enrich IP addresses, perform automated response, or prove malicious intent.

Potential future improvements: rolling-window thresholds, IP/account correlation, configurable YAML rules, structured logging, risk scoring, dashboards, and a documented comparison with a dedicated SIEM lab.

Ethics and scope
The included data is fictional and intended for defensive education. Only analyze real logs when you are authorized to access and process them.
