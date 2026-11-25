param(
    [string]$Profile = 'default',
    [string]$Region = 'ap-southeast-2',
    [string]$InstanceId = 'i-01035a72245c2fd7f'
)

$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot 'bootstrap-demo-ec2.sh'
$script = (Get-Content -LiteralPath $source -Raw) -replace "`r`n", "`n"
$command = "bash -s <<'PATHGUARD_SCRIPT'`n$script`nPATHGUARD_SCRIPT"
$request = @{
    InstanceIds = @($InstanceId)
    DocumentName = 'AWS-RunShellScript'
    Parameters = @{ commands = @($command) }
    Comment = 'Bootstrap public GitHub CI connector on PathGuard demo instance'
} | ConvertTo-Json -Depth 6
$temporary = Join-Path $env:TEMP ('pathguard-cicd-bootstrap-' + [guid]::NewGuid().ToString('N') + '.json')
try {
    [IO.File]::WriteAllText($temporary, $request, [Text.UTF8Encoding]::new($false))
    $commandId = (aws ssm send-command --profile $Profile --region $Region `
        --cli-input-json "file://$temporary" --query 'Command.CommandId' --output text).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $commandId) { throw 'SSM did not accept the bootstrap command.' }
}
finally {
    Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
}

for ($attempt = 0; $attempt -lt 30; $attempt++) {
    Start-Sleep -Seconds 5
    $result = aws ssm get-command-invocation --profile $Profile --region $Region `
        --command-id $commandId --instance-id $InstanceId --output json | ConvertFrom-Json
    if ($result.Status -in @('Success', 'Failed', 'Cancelled', 'TimedOut')) {
        Write-Host "SSM status: $($result.Status)"
        Write-Host $result.StandardOutputContent
        if ($result.StandardErrorContent) { Write-Warning $result.StandardErrorContent }
        if ($result.Status -ne 'Success') { exit 1 }
        exit 0
    }
}
throw "SSM command $commandId did not finish within 150 seconds."
