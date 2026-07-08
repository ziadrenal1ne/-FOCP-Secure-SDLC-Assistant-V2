# FOCP Secure SDLC Assistant

[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010%202021-red.svg)](https://owasp.org/Top10/)

**FOCP Secure SDLC Assistant** is a professional desktop and CLI security analysis tool designed for software developers, cybersecurity engineers, application security engineers, DevSecOps engineers, and software architects.

It scans software projects, evaluates security best practices, detects common weaknesses, and generates comprehensive reports — **without ever modifying your project files**.

---

## Which file to run?

| Platform | Run this file | Mode |
|----------|---------------|------|
| **Linux / Omarchy** | [`RUN-ON-LINUX.sh`](RUN-ON-LINUX.sh) | Terminal CLI |
| **Linux GUI** | [`RUN-ON-LINUX-GUI.sh`](RUN-ON-LINUX-GUI.sh) | Desktop GUI |
| **Windows 11** | [`RUN-ON-WINDOWS.bat`](RUN-ON-WINDOWS.bat) | Desktop GUI |
| **Windows 11 CLI** | [`RUN-ON-WINDOWS-CLI.bat`](RUN-ON-WINDOWS-CLI.bat) | Terminal CLI |

See [`WHICH-PLATFORM.txt`](WHICH-PLATFORM.txt) or [`PLATFORM-GUIDE.md`](PLATFORM-GUIDE.md) for full details.

```bash
# Linux / Omarchy
./RUN-ON-LINUX.sh scan ~/Projects/myapp
```

```cmd
REM Windows 11
RUN-ON-WINDOWS-CLI.bat scan C:\Projects\myapp
RUN-ON-WINDOWS.bat
```

---

## Table of Contents

- [Which file to run?](#which-file-to-run)
- [Purpose](#purpose)
- [Features](#features)
- [Supported Projects](#supported-projects)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Usage](#cli-usage)
- [GUI Usage](#gui-usage)
- [Configuration](#configuration)
- [Report Formats](#report-formats)
- [Building Executables](#building-executables)
- [Screenshots](#screenshots)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Future Improvements](#future-improvements)
- [Contributing](#contributing)
- [License](#license)

---

## Purpose

Modern software development requires integrating security throughout the Software Development Life Cycle (SDLC). FOCP Secure SDLC Assistant helps teams:

- **Identify** security weaknesses before they reach production
- **Understand** why each finding is dangerous and its business impact
- **Map** findings to OWASP Top 10 2021 categories
- **Remediate** with actionable recommendations, code examples, and references
- **Report** professionally to stakeholders in HTML, Markdown, PDF, and JSON

> **Important:** This tool is for defensive security analysis only. It analyzes and recommends — it never edits project files automatically.

---

## Features

### Core Analysis

| Feature | Description |
|---------|-------------|
| **Project Scanner** | Detects languages, frameworks, dependencies, Docker, Git, and configuration files |
| **Authentication Review** | Password hashing, JWT, session management, MFA detection |
| **Authorization Review** | RBAC, missing authorization, admin endpoints, privilege escalation |
| **OWASP Top 10 2021** | Full analysis against all 10 categories with severity ratings |
| **Secrets Scanner** | API keys, AWS/Azure keys, passwords, JWT secrets, private keys, high-entropy strings |
| **SQL Injection Review** | Dynamic SQL, unsafe concatenation, missing parameterized queries |
| **XSS Review** | Dangerous rendering, unsafe HTML, missing sanitization |
| **File Upload Review** | Extension validation, size limits, path traversal, web-accessible storage |
| **Security Headers** | CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| **Dependency Analysis** | Bandit, Semgrep, Trivy integration with built-in fallback checks |

### Advanced Features

| Feature | Description |
|---------|-------------|
| **Architecture Review** | Project tree, dependency graph, entry points, data stores |
| **Threat Modeling** | STRIDE-based threat table with attack surfaces and mitigations |
| **Risk Matrix** | Likelihood × Impact scoring with risk levels |
| **RBAC Matrix** | Auto-generated role-permission-resource matrix |
| **Security Checklists** | OWASP, Secure SDLC, and Deployment checklists |
| **Security Score** | 0–100 score with category breakdown and letter grade |
| **AI Recommendations** | Enhanced findings with business impact, fixes, and references |
| **Professional Reports** | HTML, Markdown, PDF, JSON export |

### Interfaces

- **Desktop GUI** — Dark-themed PySide6 application with dashboard, charts, and findings explorer
- **Terminal CLI** — Rich-formatted Typer CLI for automation and CI/CD integration

---

## Supported Projects

| Language / Platform | Detection Method |
|---------------------|------------------|
| Python | `.py`, `requirements.txt`, `pyproject.toml` |
| Java / Spring Boot | `.java`, `pom.xml`, `build.gradle` |
| Node.js / Express | `package.json`, `.js` |
| React / Next.js | `package.json`, `.jsx`, `.tsx`, `next.config.js` |
| PHP / Laravel | `.php`, `composer.json` |
| .NET / C# | `.cs`, `.csproj`, `.sln` |
| Docker | `Dockerfile`, `docker-compose.yml` |
| Git repositories | `.git` directory analysis |

---

## Architecture

The project follows **Clean Architecture** principles with SOLID design:

```
scanner/
├── config.yaml                 # Application configuration
├── pyproject.toml              # Package definition
├── requirements.txt            # Dependencies
├── src/focp_sec/
│   ├── cli/                    # Typer CLI commands
│   │   └── main.py
│   ├── gui/                    # PySide6 desktop application
│   │   ├── app.py
│   │   ├── main_window.py
│   │   ├── dashboard.py
│   │   ├── findings_view.py
│   │   ├── charts.py
│   │   └── styles.py
│   ├── core/                   # Core business logic
│   │   ├── config.py           # Configuration management
│   │   ├── models.py           # Data models
│   │   ├── scanner.py          # File discovery
│   │   ├── orchestrator.py     # Scan pipeline
│   │   └── database.py         # SQLite scan history
│   ├── analyzers/              # Security analyzers (Strategy pattern)
│   │   ├── base.py
│   │   ├── secrets_scanner.py
│   │   ├── auth_reviewer.py
│   │   ├── authz_reviewer.py
│   │   ├── owasp_analyzer.py
│   │   ├── sqli_analyzer.py
│   │   ├── xss_analyzer.py
│   │   ├── file_upload_analyzer.py
│   │   ├── headers_analyzer.py
│   │   ├── dependency_analyzer.py
│   │   ├── architecture_reviewer.py
│   │   ├── threat_modeler.py
│   │   ├── risk_matrix.py
│   │   ├── rbac_generator.py
│   │   ├── checklist_generator.py
│   │   ├── security_scorer.py
│   │   └── recommendation_engine.py
│   ├── integrations/           # External tool runners
│   │   ├── bandit_runner.py
│   │   ├── semgrep_runner.py
│   │   └── trivy_runner.py
│   ├── reports/                # Report generation
│   │   └── generator.py
│   └── templates/              # Jinja2 report templates
│       ├── report.html
│       └── report.md
└── tests/                      # Unit tests
    ├── sample_project/         # Intentionally vulnerable test project
    └── test_analyzers.py
```

### Scan Pipeline

```
Project Path
    │
    ▼
File Discovery (ProjectScanner)
    │
    ▼
Technology Detection (ProjectDetector)
    │
    ▼
Parallel Security Analyzers ──► Secrets, Auth, AuthZ, OWASP, SQLi, XSS, Upload, Headers
    │
    ▼
Dependency Analysis ──► Bandit + Semgrep + Trivy (parallel)
    │
    ▼
Recommendation Enhancement
    │
    ▼
Post-Processing ──► Architecture, Threat Model, Risk Matrix, RBAC, Checklists, Score
    │
    ▼
Report Generation + SQLite Storage
```

---

## Installation

### Prerequisites

- **Python 3.13+** (3.14 also supported)
- **pip** (Python package manager)
- **Optional:** [Bandit](https://bandit.readthedocs.io/), [Semgrep](https://semgrep.dev/), [Trivy](https://trivy.dev/) for enhanced dependency scanning

### Step 1: Clone the Repository

```bash
git clone https://github.com/your-org/focp-sec.git
cd focp-sec
```

### Step 2: Create Virtual Environment

**Linux / macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell):**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**Windows (CMD):**

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

### Step 3: Install Dependencies

```bash
pip install --upgrade pip
pip install -e .
```

For development (includes pytest, pyinstaller):

```bash
pip install -e ".[dev]"
```

### Step 4: Install Optional Security Tools

```bash
# Bandit (Python security linter) — included as dependency
pip install bandit

# Semgrep (multi-language static analysis)
pip install semgrep
# OR: curl -L https://semgrep.dev/install.sh | sh

# Trivy (vulnerability scanner)
# Linux:
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
# macOS:
brew install trivy
```

### Step 5: Verify Installation

```bash
focp-sec --version
focp-sec scan tests/sample_project/
```

---

## Quick Start

```bash
# Scan a project from CLI
focp-sec scan /path/to/your/project/

# Get security score only
focp-sec score /path/to/your/project/

# Launch GUI
focp-sec gui
# OR
focp-sec-gui
```

---

## CLI Usage

### `focp-sec scan`

Scan a project and generate reports.

```bash
focp-sec scan myproject/
focp-sec scan myproject/ --output ./reports/
focp-sec scan myproject/ --format html,pdf
focp-sec scan myproject/ --no-report
focp-sec scan myproject/ --verbose
```

### `focp-sec score`

Calculate and display security score.

```bash
focp-sec score myproject/
```

### `focp-sec report`

Generate report from a previous scan.

```bash
focp-sec report abc123def456 --format html,pdf
```

### `focp-sec checklist`

Generate security checklists.

```bash
focp-sec checklist myproject/
focp-sec checklist myproject/ --type owasp
focp-sec checklist myproject/ --type sdlc
focp-sec checklist myproject/ --type deployment
```

### `focp-sec threats`

Generate STRIDE threat model.

```bash
focp-sec threats myproject/
```

### `focp-sec dependencies`

Run dependency vulnerability analysis.

```bash
focp-sec dependencies myproject/
```

### `focp-sec rbac`

Generate RBAC matrix.

```bash
focp-sec rbac myproject/
```

### `focp-sec list-scans`

List recent scans from database.

```bash
focp-sec list-scans
focp-sec list-scans --limit 10
```

### `focp-sec gui`

Launch the desktop GUI.

```bash
focp-sec gui
```

---

## GUI Usage

### Launching the GUI

```bash
focp-sec gui
# OR
focp-sec-gui
# OR
python -m focp_sec.gui.app
```

### Workflow

1. **Open Project** — Click "Scan Project" or use `File → Open Project` (`Ctrl+O`)
2. **Run Scan** — Scan starts automatically or press `F5`
3. **Review Dashboard** — View security score, severity charts, and project summary
4. **Explore Findings** — Navigate to Findings tab for detailed analysis
5. **Review Risk Matrix** — See likelihood × impact scoring
6. **Export Report** — Click "Export Report" or `Ctrl+E` to save HTML/PDF/JSON

### GUI Navigation

| Sidebar Item | Description |
|--------------|-------------|
| Dashboard | Score gauge, severity charts, project overview |
| Findings | Searchable findings table with detail panel |
| Risk Matrix | Likelihood/impact risk scoring |
| Threat Model | STRIDE threat analysis table |
| RBAC Matrix | Role-based access control matrix |
| Checklists | OWASP, SDLC, Deployment checklists |
| Architecture | Project tree and architecture summary |

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+O` | Open project |
| `F5` | Run scan |
| `Ctrl+E` | Export report |
| `Ctrl+Q` | Quit |

---

## Configuration

Configuration is loaded from `config.yaml` in the project root or `~/.focp-sec/config.yaml`.

```yaml
app:
  name: "FOCP Secure SDLC Assistant"
  log_level: "INFO"
  max_workers: 4          # Parallel analysis workers

scan:
  exclude_dirs:           # Directories to skip
    - node_modules
    - .git
    - __pycache__
  max_file_size_mb: 5     # Skip files larger than this
  secrets_entropy_threshold: 4.5

tools:
  bandit:
    enabled: true
  semgrep:
    enabled: true
  trivy:
    enabled: true

scoring:
  weights:                # Category weights for overall score
    authentication: 15
    authorization: 15
    configuration: 10
    dependencies: 20
    secrets: 20
    logging: 5
    encryption: 15

report:
  output_dir: "./reports"
  formats:
    - html
    - markdown
    - pdf
    - json
  company_name: "FOCP Security"

database:
  path: "~/.focp-sec/scans.db"

gui:
  theme: "dark"
  window_width: 1400
  window_height: 900
```

---

## Report Formats

### HTML Report
Professional dark-themed report with cover page, executive summary, findings, risk matrix, threat model, RBAC matrix, checklists, and architecture summary. Suitable for sharing with stakeholders.

### Markdown Report
GitHub-compatible markdown format ideal for wikis, documentation, and version control.

### PDF Report
Print-ready PDF with cover page, tables, and formatted findings. Generated using ReportLab.

### JSON Report
Machine-readable format for CI/CD integration, custom tooling, and API consumption.

Example JSON structure:

```json
{
  "scan_id": "abc123",
  "project": { "name": "my-app", "languages": ["Python"] },
  "score": { "overall": 72.5, "grade": "C" },
  "findings": [
    {
      "title": "Hardcoded API Key Detected",
      "severity": "high",
      "owasp_category": "A02:2021-Cryptographic Failures",
      "recommendation": "Move secrets to environment variables..."
    }
  ],
  "summary": { "total_findings": 15, "critical": 2, "high": 5 }
}
```

---

## Building Executables

### Linux Binary

```bash
pip install pyinstaller
pyinstaller focp-sec-gui.spec
# Output: dist/focp-sec-gui
```

One-file CLI binary:

```bash
pyinstaller --onefile --name focp-sec \
  --add-data "src/focp_sec/templates:focp_sec/templates" \
  --add-data "config.yaml:." \
  --paths src \
  src/focp_sec/cli/main.py
```

### Windows EXE

```powershell
pip install pyinstaller
pyinstaller focp-sec-gui.spec
# Output: dist\focp-sec-gui.exe
```

For CLI on Windows:

```powershell
pyinstaller --onefile --name focp-sec ^
  --add-data "src/focp_sec/templates;focp_sec/templates" ^
  --add-data "config.yaml;." ^
  --paths src ^
  src/focp_sec/cli/main.py
```

---

## Screenshots

> Screenshots will be added in a future release. Below are placeholders describing each view.

### Dashboard
<!-- ![Dashboard](docs/screenshots/dashboard.png) -->
*Security score gauge, severity distribution chart, category score bars, and project summary card.*

### Findings Explorer
<!-- ![Findings](docs/screenshots/findings.png) -->
*Sortable findings table with severity color coding and detailed finding panel with remediation guidance.*

### Risk Matrix
<!-- ![Risk Matrix](docs/screenshots/risk-matrix.png) -->
*Likelihood × Impact matrix with color-coded risk levels.*

### CLI Output
<!-- ![CLI](docs/screenshots/cli.png) -->
*Rich-formatted terminal output with progress bar, score summary, and findings table.*

---

## Troubleshooting

### "Bandit/Semgrep/Trivy not available"

These tools are optional. The scanner uses built-in checks when external tools are unavailable. Install them for enhanced analysis:

```bash
pip install bandit semgrep
# Trivy: see installation section above
```

### PySide6 GUI won't launch

Ensure display server is available (Linux):

```bash
# Check DISPLAY variable
echo $DISPLAY

# For headless systems, GUI is not supported
# Use CLI instead: focp-sec scan myproject/
```

### Scan is slow on large projects

Adjust configuration:

```yaml
app:
  max_workers: 8    # Increase parallel workers
scan:
  exclude_dirs:     # Add more directories to exclude
    - vendor
    - target
```

### Permission denied on project path

Ensure read access to the project directory:

```bash
ls -la /path/to/project
chmod -R u+r /path/to/project  # If needed
```

### PDF generation fails

Ensure ReportLab is installed:

```bash
pip install reportlab
```

---

## FAQ

**Q: Does this tool modify my code?**
A: No. FOCP Secure SDLC Assistant only reads and analyzes files. It never edits, deletes, or modifies project files.

**Q: Can I use this in CI/CD?**
A: Yes. Use the CLI with JSON output:
```bash
focp-sec scan . --format json --output ./reports/
```

**Q: How is the security score calculated?**
A: Each category starts at 100 and penalties are applied based on finding severity (Critical: -25, High: -15, Medium: -8, Low: -3). Categories are weighted and combined for the overall score.

**Q: What OWASP version is supported?**
A: OWASP Top 10 2021.

**Q: Does it work offline?**
A: Yes. All analysis runs locally. External tools (Bandit, Semgrep, Trivy) also work offline after installation.

**Q: How do I add custom rules?**
A: Extend `BaseAnalyzer` in `src/focp_sec/analyzers/` and register it in `ScanOrchestrator.ANALYZERS`.

---

## Future Improvements

- [ ] SARIF output format for IDE integration
- [ ] CI/CD GitHub Action
- [ ] Custom rule YAML configuration
- [ ] Incremental/differential scanning
- [ ] Multi-project comparison dashboard
- [ ] Integration with GitHub/GitLab Security Dashboards
- [ ] Tree-sitter AST-based analysis for deeper code inspection
- [ ] Plugin system for third-party analyzers
- [ ] Compliance frameworks (PCI-DSS, HIPAA, SOC 2)
- [ ] Real-time scanning file watcher mode

---

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for new functionality
4. Ensure all tests pass (`pytest tests/`)
5. Submit a Pull Request

### Development Setup

```bash
git clone https://github.com/your-org/focp-sec.git
cd focp-sec
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -v
```

### Code Style

- Type hints on all functions
- Docstrings on all public modules and functions
- Follow existing patterns in analyzers and core modules
- Run `ruff check src/` before committing

---

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=focp_sec --cov-report=html

# Run specific test
pytest tests/test_analyzers.py::TestSecretsScanner -v
```

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgments

- [OWASP Foundation](https://owasp.org/) for security standards and cheat sheets
- [Bandit](https://bandit.readthedocs.io/) for Python security analysis
- [Semgrep](https://semgrep.dev/) for multi-language static analysis
- [Trivy](https://trivy.dev/) for vulnerability scanning
- [ReportLab](https://www.reportlab.com/) for PDF generation

---

<p align="center">
  <strong>FOCP Secure SDLC Assistant</strong> — Building secure software, one scan at a time.
</p>
