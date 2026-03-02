# Open-Source Release Checklist (A.V.A.R.S)

Use this checklist before pushing changes to a public repository.

## 1) Safety & Licensing
- [ ] `LICENSE` exists and uses MIT text
- [ ] `README.md` includes legal and authorized-use notice
- [ ] No local-only evidence files or penetration logs are present

## 2) Secret Hygiene
- [ ] No `terraform.tfstate` / `*.tfstate.*` files in repository
- [ ] No `terraform.tfvars` with real subscription/tenant values in repository
- [ ] `.gitignore` includes local envs, state, reports, and evidence folders
- [ ] Secret sweep returns placeholders only (example env references are allowed)

## 3) Local Validation
- [ ] Quick checks pass:
  - `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run_all_checks.ps1 -Quick`
- [ ] Full checks pass:
  - `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run_all_checks.ps1 -IncludeRiskRun`

## 4) GitHub Actions Behavior
- [ ] Scan workflow parses without schema errors
- [ ] Deploy job is opt-in only (`workflow_dispatch` + `run_deploy=true`)

## 5) User Onboarding Quality
- [ ] `README.md` has clone-to-first-run instructions
- [ ] `docs/DEPLOYMENT.md` has browser-first phased setup
- [ ] `CONTRIBUTING.md` documents local validation before PR

## 6) Publish
- [ ] Commit message clearly states release readiness
- [ ] Push branch and verify Actions security scan completes
