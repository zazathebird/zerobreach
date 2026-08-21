$ErrorActionPreference = "Stop"
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$BranchName = "work-sync-$Timestamp"
$RepoUrl = "origin"

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host " WORK BRANCH SYNC - STARTING                     " -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

try {
# 1. Ensure we don't accidentally try to commit empty air
$GitStatus = git status --porcelain
if ([string]::IsNullOrWhiteSpace($GitStatus)) {
Write-Host "[INFO] No changes detected. Your working directory is clean." -ForegroundColor Green
Write-Host "Nothing to sync." -ForegroundColor Green
exit
}

Write-Host "[!] Changes detected. Staging files..." -ForegroundColor Cyan

# 2. Create and switch to the completely isolated quarantine branch
git checkout -b $BranchName | Out-Null
Write-Host "[OK] Isolated branch created: $BranchName" -ForegroundColor Green

# 3. Add all modified, deleted, and untracked files to the staging area
git add .

# 4. Seal the container with a descriptive commit message
$CommitMsg = "Raw automated session dump from work rig - $Timestamp"
git commit -m $CommitMsg | Out-Null
Write-Host "[OK] Changes committed locally." -ForegroundColor Green

# 5. Shove it up to GitHub. The '-u' sets the upstream link so it tracks properly.
Write-Host "[!] Pushing branch to GitHub ($RepoUrl)..." -ForegroundColor Cyan
git push -u origin $BranchName

Write-Host "=================================================" -ForegroundColor Green
Write-Host " SYNC SUCCESSFUL. WORK IS SAFE ON THE REMOTE.    " -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Green
Write-Host "When you get home, run: git fetch && git checkout $BranchName" -ForegroundColor Yellow


} catch {
Write-Host "[ERROR] Sync failed." -ForegroundColor Red
Write-Host $_.Exception.Message -ForegroundColor Red
Write-Host "Dropping you back to main branch..." -ForegroundColor Yellow

# Attempt to gracefully drop back to main if the branch creation failed
git checkout main | Out-Null
exit 1


}