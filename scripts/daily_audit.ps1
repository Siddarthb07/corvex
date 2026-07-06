# Daily audit + conditional commit (honest trail)
# Usage: powershell -File scripts/daily_audit.ps1
# Commits only if the working tree changed after the audit.

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)
$env:PYTHONIOENCODING = "utf-8"

$date = Get-Date -Format "yyyy-MM-dd"
Write-Host "== CampaignFuse daily audit $date =="

python -m pytest -q
if ($LASTEXITCODE -ne 0) { throw "pytest failed — not committing" }

python -m campaignfuse.cli seal-day0 --force
python -m campaignfuse.cli eval --split train
python -m campaignfuse.cli eval --split heldout
python -m campaignfuse.cli dash --build

# Refresh compact audit JSON
python -c @"
import json
from pathlib import Path
from campaignfuse.dashboard import collect_snapshot
from campaignfuse.contain import contain_status
from campaignfuse.stage_c import stage_c_ready
from campaignfuse import CFUSE_CONTAIN, __version__
root = Path('.')
snap = collect_snapshot(root)
audit = {
  'date': '$date',
  'version': __version__,
  'CFUSE_CONTAIN': CFUSE_CONTAIN,
  'snapshot': snap,
  'stage_c': stage_c_ready(),
  'stage_d': contain_status(),
}
Path('reports/daily').mkdir(parents=True, exist_ok=True)
Path('reports/daily/$date.json').write_text(json.dumps(audit, indent=2), encoding='utf-8')
Path('reports/AUDIT_BENCHMARK.json').write_text(json.dumps(audit, indent=2), encoding='utf-8')
print('gate', snap.get('gate'), 'd_pct', snap['stage_d']['checklist_pct'])
"@

git add -A
$status = git status --porcelain
if (-not $status) {
  Write-Host "NO_CHANGES — skipping commit (honest empty day)"
  exit 0
}

# Avoid committing local secrets if ever misplaced
if (Test-Path .campaignfuse) { git reset -q .campaignfuse 2>$null }

$msg = @"
audit: daily bake-off refresh $date

Regenerate seal/eval/dashboard artifacts; commit only when tree dirty.
"@

git commit -m $msg
Write-Host "COMMITTED"
# Push only if upstream exists — never force
$upstream = git rev-parse --abbrev-ref --symbolic-full-name "@{u}" 2>$null
if ($LASTEXITCODE -eq 0 -and $upstream) {
  git push
  Write-Host "PUSHED $upstream"
} else {
  Write-Host "No upstream set — commit local only. Run: git push -u origin HEAD"
}
