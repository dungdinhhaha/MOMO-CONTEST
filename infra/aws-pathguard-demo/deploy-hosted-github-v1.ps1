$ErrorActionPreference = 'Stop'
$profile = 'default'
$region = 'ap-southeast-2'
$instance = 'i-01035a72245c2fd7f'
$expectedAccount = '920235987407'
$image = '920235987407.dkr.ecr.ap-southeast-2.amazonaws.com/pathguard/demo-api@sha256:d4393291523a3202c0c37b263dfe8fd169720c24260fe64ac71b36d26cb476f6'
$identity = aws sts get-caller-identity --profile $profile | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $identity.Account -ne $expectedAccount) {
    throw 'AWS profile default is not the PathGuard application account.'
}

$remote = (@'
set -euo pipefail
cd /opt/pathguard
image="920235987407.dkr.ecr.ap-southeast-2.amazonaws.com/pathguard/demo-api@sha256:d4393291523a3202c0c37b263dfe8fd169720c24260fe64ac71b36d26cb476f6"
cfg="$(mktemp -d /run/pathguard-ecr-XXXXXX)"
chmod 700 "$cfg"
trap 'rm -rf "$cfg"' EXIT
aws ecr get-login-password --region ap-southeast-2 | docker --config "$cfg" login --username AWS --password-stdin 920235987407.dkr.ecr.ap-southeast-2.amazonaws.com >/dev/null
docker --config "$cfg" pull "$image" >/dev/null
sed -i "s|^    image: .*pathguard/demo-api.*$|    image: $image|" compose.yaml
docker compose --env-file .env -f compose.yaml up -d --no-deps api
docker compose --env-file .env -f compose.yaml ps api
'@) -replace "`r`n", "`n"
$request = @{
    InstanceIds = @($instance)
    DocumentName = 'AWS-RunShellScript'
    Parameters = @{ commands = @($remote) }
    Comment = 'Deploy PathGuard tenant self-service public GitHub source API'
} | ConvertTo-Json -Depth 6
$temporary = Join-Path $env:TEMP ('pathguard-hosted-github-' + [guid]::NewGuid().ToString('N') + '.json')
try {
    [IO.File]::WriteAllText($temporary, $request, [Text.UTF8Encoding]::new($false))
    $commandId = (aws ssm send-command --profile $profile --region $region `
        --cli-input-json "file://$temporary" --query 'Command.CommandId' --output text).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $commandId) { throw 'SSM rejected the deployment command.' }
}
finally {
    Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
}

$finished = $false
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    Start-Sleep -Seconds 5
    $result = aws ssm get-command-invocation --profile $profile --region $region `
        --command-id $commandId --instance-id $instance --output json | ConvertFrom-Json
    if ($result.Status -in @('Success', 'Failed', 'Cancelled', 'TimedOut')) {
        Write-Host "SSM status: $($result.Status)"
        Write-Host $result.StandardOutputContent
        if ($result.StandardErrorContent) { Write-Warning $result.StandardErrorContent }
        if ($result.Status -ne 'Success') { exit 1 }
        $finished = $true
        break
    }
}
if (-not $finished) { throw "SSM command $commandId did not finish within 150 seconds." }

for ($attempt = 0; $attempt -lt 20; $attempt++) {
    try {
        $health = Invoke-RestMethod 'https://pathguard.parkinguth.sbs/actuator/health' -TimeoutSec 5
        if ($health.status -eq 'UP') { Write-Host 'PathGuard API health: UP'; exit 0 }
    } catch { }
    Start-Sleep -Seconds 3
}
throw 'The new API did not become healthy.'
