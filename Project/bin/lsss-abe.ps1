param(
    [Parameter(Mandatory)][ValidateSet("setup","keygen","encrypt","decrypt")][string]$Command,
    [ValidateSet("exponent","pairing")][string]$Adapter = "exponent",
    [string]$Python,
    [string]$OutDir,
    [string]$Pub,
    [string]$Msk,
    [string]$Sk,
    [string]$Policy,
    [string]$In,
    [string]$Out,
    [string]$Attrs
)

$ErrorActionPreference = "Stop"

function Resolve-PairingPython {
    if ($Python) { return $Python }

    $projectRoot = Split-Path -Parent $PSScriptRoot
    $repoRoot = Split-Path -Parent $projectRoot
    $candidate = Join-Path $repoRoot "env\python.exe"
    if (Test-Path -LiteralPath $candidate) { return $candidate }

    "python"
}

function Invoke-PairingBackend {
    param([Parameter(Mandatory)][string[]]$BackendArgs)

    $backendPath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\src\LsssAbe\pairing_backend.py")).Path
    $pythonExe = Resolve-PairingPython
    $oldErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $pythonExe $backendPath @BackendArgs 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $oldErrorActionPreference
    }
    if ($exitCode -ne 0) {
        $message = ($output | Out-String).Trim()
        if (-not $message) { $message = "Pairing backend failed with exit code $exitCode." }
        throw $message
    }
    if ($output) { $output | Write-Output }
}

if ($Adapter -eq "pairing") {
    switch ($Command) {
        "setup" {
            if (-not $OutDir) { throw "-OutDir is required." }
            Invoke-PairingBackend -BackendArgs @("setup", "--out-dir", $OutDir)
            break
        }
        "keygen" {
            if (-not $Pub) { throw "-Pub is required." }
            if (-not $Msk) { throw "-Msk is required." }
            if (-not $Attrs) { throw '-Attrs is required, e.g. "A,B".' }
            if (-not $OutDir) { $OutDir = Split-Path -Parent $Msk }
            Invoke-PairingBackend -BackendArgs @("keygen", "--pub", $Pub, "--msk", $Msk, "--attrs", $Attrs, "--out-dir", $OutDir)
            break
        }
        "encrypt" {
            if (-not $Pub) { throw "-Pub is required." }
            if (-not $Policy) { throw "-Policy is required." }
            if (-not $In) { throw "-In is required." }
            if (-not $Out) { throw "-Out is required." }
            Invoke-PairingBackend -BackendArgs @("encrypt", "--pub", $Pub, "--policy", $Policy, "--input", $In, "--output", $Out)
            break
        }
        "decrypt" {
            if (-not $Pub) { throw "-Pub is required." }
            if (-not $Sk) { throw "-Sk is required." }
            if (-not $In) { throw "-In is required." }
            if (-not $Out) { throw "-Out is required." }
            Invoke-PairingBackend -BackendArgs @("decrypt", "--pub", $Pub, "--sk", $Sk, "--input", $In, "--output", $Out)
            break
        }
    }
    return
}

$modulePath = Join-Path $PSScriptRoot "..\\src\\LsssAbe\\LsssAbe.psm1"
Import-Module $modulePath -Force

function Read-Bytes {
    param([Parameter(Mandatory)][string]$Path)
    [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path).Path)
}

function Write-Bytes {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][byte[]]$Bytes
    )
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    [System.IO.File]::WriteAllBytes($Path, $Bytes)
}

function ConvertTo-SafeFileNamePart {
    param([Parameter(Mandatory)][string]$Text)

    $safe = $Text -replace '[\\/:*?"<>|]', '_'
    $safe = $safe -replace '\s+', '_'
    $safe = $safe.Trim(" ._")
    if ($safe -eq "") { $safe = "attr" }
    $safe
}

switch ($Command) {
    "setup" {
        if (-not $OutDir) { throw "-OutDir is required." }
        $keys = New-LsssAbeSetup
        ConvertTo-LsssAbeJsonFile -Object $keys.public -Path (Join-Path $OutDir "public.json")
        ConvertTo-LsssAbeJsonFile -Object $keys.master -Path (Join-Path $OutDir "master.json")
        break
    }
    "keygen" {
        if (-not $Pub) { throw "-Pub is required." }
        if (-not $Msk) { throw "-Msk is required." }
        if (-not $Attrs) { throw '-Attrs is required, e.g. "A,B".' }
        if (-not $OutDir) { $OutDir = Split-Path -Parent $Msk }
        $public = ConvertFrom-LsssAbeJsonFile -Path $Pub
        $master = ConvertFrom-LsssAbeJsonFile -Path $Msk
        $attrArr = $Attrs.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
        $skObj = New-LsssAbeKeyGen -Public $public -Master $master -Attrs $attrArr
        $safeAttrs = $attrArr | ForEach-Object { ConvertTo-SafeFileNamePart -Text $_ }
        $name = "sk_" + ($safeAttrs -join "_") + ".json"
        ConvertTo-LsssAbeJsonFile -Object $skObj -Path (Join-Path $OutDir $name)
        break
    }
    "encrypt" {
        if (-not $Pub) { throw "-Pub is required." }
        if (-not $Policy) { throw "-Policy is required." }
        if (-not $In) { throw "-In is required." }
        if (-not $Out) { throw "-Out is required." }
        $public = ConvertFrom-LsssAbeJsonFile -Path $Pub
        $policyObj = ConvertFrom-LsssAbeJsonFile -Path $Policy
        $plainBytes = Read-Bytes -Path $In
        $ct = New-LsssAbeEncrypt -Public $public -PolicyTree $policyObj -PlainBytes $plainBytes
        ConvertTo-LsssAbeJsonFile -Object $ct -Path $Out
        break
    }
    "decrypt" {
        if (-not $Pub) { throw "-Pub is required." }
        if (-not $Sk) { throw "-Sk is required." }
        if (-not $In) { throw "-In is required." }
        if (-not $Out) { throw "-Out is required." }
        $public = ConvertFrom-LsssAbeJsonFile -Path $Pub
        $skObj = ConvertFrom-LsssAbeJsonFile -Path $Sk
        $ctObj = ConvertFrom-LsssAbeJsonFile -Path $In
        $plainBytes = New-LsssAbeDecrypt -Public $public -SecretKey $skObj -Ciphertext $ctObj
        Write-Bytes -Path $Out -Bytes $plainBytes
        break
    }
}
