# --------- CONFIG ---------
$Repo     = "ORG_OR_USERNAME/REPO_NAME"
$Workflow = "ci.yml"          # workflow file or name
$Branch   = "develop"
# --------------------------

Write-Host "🚀 Triggering workflow '$Workflow' on branch '$Branch'..."

gh workflow run $Workflow `
  --repo $Repo `
  --ref $Branch

# Small delay to let GitHub register the run
Start-Sleep -Seconds 5

# Get the la***REMOVED*** run ID for this workflow & branch
$RunId = gh run list `
  --repo $Repo `
  --workflow $Workflow `
  --branch $Branch `
  --limit 1 `
  --json databaseId `
  -q '.[0].databaseId'

if (-not $RunId) {
    Write-Error "❌ Unable to find workflow run"
    exit 1
}

Write-Host "⏳ Waiting for workflow run ID: $RunId"

# Wait until workflow completes
gh run watch $RunId --repo $Repo

# Get final conclusion
$Conclusion = gh run view $RunId `
  --repo $Repo `
  --json conclusion `
  -q '.conclusion'

Write-Host "🏁 Workflow completed with status: $Conclusion"

# Fail script if workflow failed
if ($Conclusion -ne "success") {
    Write-Error "❌ Workflow failed."
    exit 1
}

Write-Host "✅ Workflow succeede.d"
