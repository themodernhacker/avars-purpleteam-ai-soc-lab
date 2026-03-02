# Contributing to Project A.V.A.R.S

Thanks for your interest in contributing. This project is intended for learning, demonstration, and authorized testing in controlled environments. Contributions that improve documentation, tests, detection rules, and safe automation are especially welcome.

## Code of Conduct
- Be respectful, constructive, and helpful.
- Do not post offensive or illegal content.
- Follow the project's legal & safe use guidance in `README.md`—offensive tooling must only be used in authorized labs.

## How to Contribute
1. Fork the repository.
2. Create a feature branch from `main` named using the pattern: `feat/<short-description>` or `fix/<short-description>`.
3. Make changes in your branch and run local validation:
	- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run_all_checks.ps1 -Quick`
4. If your change touches scripts/infra behavior, run full checks:
	- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run_all_checks.ps1 -IncludeRiskRun`
4. Open a Pull Request describing the change and reference any related issue.
5. Request review from the maintainers.

## PR Checklist
- [ ] Follow repository coding standards (PEP8 for Python).
- [ ] Include tests for new functionality when applicable.
- [ ] Update documentation (`README.md` or `docs/`) where relevant.
- [ ] Do not commit secrets or credentials.

## Branching and Naming
- `main` — stable, production-ready
- `dev` — active development (if used)
- Feature branches: `feat/<name>`
- Bugfix branches: `fix/<name>`

## Running Tests & Linters
```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate
pip install -r ml-notebooks/requirements.txt
# Run lint
flake8 .
# Run tests
pytest
```

## Reporting Security Issues
If you discover a vulnerability or security issue in the project, do not open a public issue. Use GitHub Security Advisories (private report) for this repository and include reproducible steps plus mitigation suggestions.

## Development Environment
- Python 3.10+
- Terraform 1.0+
- Azure CLI

Thank you for helping improve Project A.V.A.R.S.