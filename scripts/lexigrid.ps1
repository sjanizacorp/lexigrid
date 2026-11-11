# LexiGrid lifecycle, Windows PowerShell 5.1+ / PowerShell 7
# Author: Shahryar Jahangir, Aniza Inc.
param(
 [Parameter(Position=0,Mandatory=$true)][ValidateSet('install','start','stop','status','uninstall')][string]$Action,
 [ValidateSet('docker','native')][string]$Mode='',
 [string]$DatabaseUrl='',
 [ValidateSet('sqlite','postgres')][string]$Database='',
 [string]$PgHost='127.0.0.1',
 [int]$PgPort=5432,
 [string]$PgDatabase='lexigrid',
 [string]$PgUser='lexigrid_owner',
 [switch]$SkipMigrations,
 [switch]$Yes
)
$ErrorActionPreference='Stop'
$Root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $Root
$ModeFile=Join-Path $Root '.lexigrid-deployment-mode'
if(-not $Mode -and (Test-Path $ModeFile)) {$Mode=(Get-Content $ModeFile -Raw).Trim()}
if(-not $Mode -and $Action -eq 'install') {
 Write-Host 'Select LexiGrid installation type:'
 Write-Host '  1) Native Python (no Docker required)'
 Write-Host '  2) Docker Compose (Docker required)'
 $choice=Read-Host 'Choose 1 or 2'
 switch($choice) {'1' {$Mode='native'} '2' {$Mode='docker'} default {throw 'Invalid installation type'}}
}
if(-not $Mode) {$Mode='docker'}
if($Mode -eq 'native') {
 $py=Get-Command py -ErrorAction SilentlyContinue
 if($py) {$exe='py';$prefix=@('-3')} else {$exe='python';$prefix=@()}
 $params=@($prefix)+@('scripts/native/manager.py',$Action)
 if($Action -eq 'install') {
  if($DatabaseUrl) {$params+=@('--database-url',$DatabaseUrl)}
  if($Database) {$params+=@('--database',$Database)}
  if($Database -eq 'postgres') {$params+=@('--pg-host',$PgHost,'--pg-port',[string]$PgPort,'--pg-database',$PgDatabase,'--pg-user',$PgUser)}
  if($SkipMigrations) {$params+='--skip-migrations'}
 }
 if($Action -eq 'uninstall' -and $Yes) {$params+='--yes'}
 & $exe @params
 if($LASTEXITCODE -eq 0 -and $Action -eq 'install') {Set-Content -Path $ModeFile -Value 'native'}
 exit $LASTEXITCODE
}
if(-not (Get-Command docker -ErrorAction SilentlyContinue)) {throw 'Docker Desktop / Docker Compose v2 required'}
if($Action -eq 'install') {
 if(-not (Test-Path '.env')) {
  $names=@('POSTGRES_OWNER_PASSWORD','RUNTIME_DB_PASSWORD','JWT_SECRET','AUDIT_HMAC_KEY','EVIDENCE_ENCRYPTION_KEY','LEXIGRID_MFA_ENCRYPTION_KEY','LEXIGRID_MAIL_CONFIG_KEY','LEXIGRID_ANCHOR_HMAC_KEY')
  $lines=@()
  foreach($name in $names) {
   $bytes=New-Object byte[] 32
   [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
   if($name -eq 'LEXIGRID_MAIL_CONFIG_KEY' -or $name -eq 'LEXIGRID_MFA_ENCRYPTION_KEY') {$value=[Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')} else {$value=[BitConverter]::ToString($bytes).Replace('-','').ToLowerInvariant()}
   $lines+="$name=$value"
  }
  $lines+=@('LEXIGRID_KMS_PROVIDER=local','LEXIGRID_WORKFLOW_SCAN_SECONDS=300','LEXIGRID_REQUIRE_MFA=1','LEXIGRID_REQUIRE_LOCAL_MFA=0')
  [System.IO.File]::WriteAllLines((Join-Path $Root '.env'),$lines,(New-Object System.Text.UTF8Encoding($false)))
  Write-Host 'Created .env. Restrict access using Windows ACLs and store a secure backup.'
 }
}
if(-not (Test-Path '.env')) {throw 'Missing .env. Run install first.'}
if($Action -eq 'install' -and -not (Select-String -Path '.env' -Pattern '^LEXIGRID_MAIL_CONFIG_KEY=' -Quiet)) {
 $bytes=New-Object byte[] 32
 [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
 $value=[Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
 Add-Content -Path '.env' -Value "LEXIGRID_MAIL_CONFIG_KEY=$value"
 Write-Host 'Added mail encryption key; existing secrets preserved.'
}
$compose=@('compose','--env-file','.env','-f','compose.yaml')
switch($Action) {
 'install' {
  & docker @compose config --quiet; if($LASTEXITCODE) {throw 'Invalid Compose config'}
  & docker @compose up -d --build --wait postgres; if($LASTEXITCODE) {throw 'Postgres failed'}
  & docker @compose run --rm migrate; if($LASTEXITCODE) {throw 'Migration failed'}
  & docker @compose up -d --build --no-deps api workflow-scheduler
 }
 'start' {
  & docker @compose up -d postgres; if($LASTEXITCODE) {throw 'Postgres failed'}
  & docker @compose run --rm migrate; if($LASTEXITCODE) {throw 'Migration failed'}
  & docker @compose up -d --no-deps api workflow-scheduler
 }
 'stop' { & docker @compose stop api workflow-scheduler postgres }
 'status' {
  & docker @compose ps
  try { $r=Invoke-WebRequest -Uri 'http://127.0.0.1:8000/health' -TimeoutSec 4 -UseBasicParsing; Write-Host "API HTTP status: $($r.StatusCode)" }
  catch { Write-Warning 'API health probe failed' }
 }
 'uninstall' {
  if(-not $Yes) { $confirmation=Read-Host 'Type UNINSTALL to remove containers (database retained)'; if($confirmation -cne 'UNINSTALL') {throw 'Cancelled'} }
  & docker @compose down --remove-orphans
  Write-Host 'Database volume and .env preserved. No data deleted.'
 }
}
if($LASTEXITCODE -ne 0) {exit $LASTEXITCODE}
if($Action -eq 'install') {Set-Content -Path $ModeFile -Value 'docker'}
