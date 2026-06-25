$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$bin = Join-Path $root "bin\lsss-abe.ps1"
$repoRoot = Split-Path -Parent $root
$python = Join-Path $repoRoot "env\python.exe"

if (-not (Test-Path -LiteralPath $python)) {
    throw "Pairing smoke test requires env python: $python"
}

$art = Join-Path $PSScriptRoot "artifacts_pairing"
if (Test-Path -LiteralPath $art) { Remove-Item -Recurse -Force -LiteralPath $art }
New-Item -ItemType Directory -Path $art | Out-Null

function Invoke-Abe {
    & $bin @args -Adapter pairing -Python $python
}

function Assert-TextEquals {
    param(
        [Parameter(Mandatory)][string]$ExpectedPath,
        [Parameter(Mandatory)][string]$ActualPath,
        [Parameter(Mandatory)][string]$Message
    )

    $expected = Get-Content -Raw -LiteralPath $ExpectedPath -Encoding UTF8
    $actual = Get-Content -Raw -LiteralPath $ActualPath -Encoding UTF8
    if ($expected -ne $actual) { throw $Message }
}

$messagePath = Join-Path $root "examples\message.txt"
$publicPath = Join-Path $art "public.json"
$masterPath = Join-Path $art "master.json"

Invoke-Abe setup -OutDir $art

# Scenario 1: {A,B} satisfies (A AND B) OR C.
Invoke-Abe keygen -Pub $publicPath -Msk $masterPath -OutDir $art -Attrs "A,B"
Invoke-Abe encrypt -Pub $publicPath -Policy (Join-Path $root "examples\policy.json") -In $messagePath -Out (Join-Path $art "ct.json")
Invoke-Abe decrypt -Pub $publicPath -Sk (Join-Path $art "sk_A_B.json") -In (Join-Path $art "ct.json") -Out (Join-Path $art "out_A_B.txt")
Assert-TextEquals -ExpectedPath $messagePath -ActualPath (Join-Path $art "out_A_B.txt") -Message "Pairing scenario 1 failed: {A,B} should decrypt."
Write-Host "Pairing scenario 1 OK: {A,B} decrypted successfully."

# Scenario 2: {C} satisfies (A AND B) OR C.
Invoke-Abe keygen -Pub $publicPath -Msk $masterPath -OutDir $art -Attrs "C"
Invoke-Abe decrypt -Pub $publicPath -Sk (Join-Path $art "sk_C.json") -In (Join-Path $art "ct.json") -Out (Join-Path $art "out_C.txt")
Assert-TextEquals -ExpectedPath $messagePath -ActualPath (Join-Path $art "out_C.txt") -Message "Pairing scenario 2 failed: {C} should decrypt."
Write-Host "Pairing scenario 2 OK: {C} decrypted successfully."

# Scenario 3: {A} does not satisfy (A AND B) OR C.
Invoke-Abe keygen -Pub $publicPath -Msk $masterPath -OutDir $art -Attrs "A"
try {
    Invoke-Abe decrypt -Pub $publicPath -Sk (Join-Path $art "sk_A.json") -In (Join-Path $art "ct.json") -Out (Join-Path $art "out_A.txt")
    throw "Pairing scenario 3 failed: {A} should be rejected."
} catch {
    if ($_.Exception.Message -notmatch "Attributes do not satisfy") {
        throw "Pairing scenario 3 failed: unexpected error: $($_.Exception.Message)"
    }
    Write-Host "Pairing scenario 3 OK: {A} correctly rejected."
}

# Scenario 4: filename-unsafe attribute name remains usable.
$specialPolicyPath = Join-Path $art "policy_special.json"
$specialCtPath = Join-Path $art "ct_special.json"
$specialOutPath = Join-Path $art "out_role_admin.txt"
[pscustomobject]@{ attr = "role:admin" } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $specialPolicyPath -Encoding UTF8
Invoke-Abe keygen -Pub $publicPath -Msk $masterPath -OutDir $art -Attrs "role:admin"
if (-not (Test-Path -LiteralPath (Join-Path $art "sk_role_admin.json"))) {
    throw "Pairing scenario 4 failed: filename-safe key was not created."
}
Invoke-Abe encrypt -Pub $publicPath -Policy $specialPolicyPath -In $messagePath -Out $specialCtPath
Invoke-Abe decrypt -Pub $publicPath -Sk (Join-Path $art "sk_role_admin.json") -In $specialCtPath -Out $specialOutPath
Assert-TextEquals -ExpectedPath $messagePath -ActualPath $specialOutPath -Message "Pairing scenario 4 failed: role:admin should decrypt."
Write-Host "Pairing scenario 4 OK: role:admin decrypted successfully."

# Scenario 5: tampered payload authentication tag is rejected.
$tamperedCtPath = Join-Path $art "ct_tampered.json"
$ctObj = Get-Content -Raw -LiteralPath (Join-Path $art "ct.json") -Encoding UTF8 | ConvertFrom-Json
$ctObj.payload.tag = [Convert]::ToBase64String((New-Object byte[] 32))
$ctObj | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $tamperedCtPath -Encoding UTF8
try {
    Invoke-Abe decrypt -Pub $publicPath -Sk (Join-Path $art "sk_A_B.json") -In $tamperedCtPath -Out (Join-Path $art "out_tampered.txt")
    throw "Pairing scenario 5 failed: tampered ciphertext should be rejected."
} catch {
    if ($_.Exception.Message -notmatch "Invalid ciphertext tag") {
        throw "Pairing scenario 5 failed: unexpected error: $($_.Exception.Message)"
    }
    Write-Host "Pairing scenario 5 OK: tampered ciphertext correctly rejected."
}

# Scenario 6: 2-of-3 threshold accepts two attributes and rejects one.
$thresholdPolicyPath = Join-Path $art "policy_2of3.json"
$thresholdCtPath = Join-Path $art "ct_2of3.json"
[pscustomobject]@{
    k = 2
    children = @(
        [pscustomobject]@{ attr = "D" },
        [pscustomobject]@{ attr = "E" },
        [pscustomobject]@{ attr = "F" }
    )
} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $thresholdPolicyPath -Encoding UTF8
Invoke-Abe keygen -Pub $publicPath -Msk $masterPath -OutDir $art -Attrs "D,F"
Invoke-Abe encrypt -Pub $publicPath -Policy $thresholdPolicyPath -In $messagePath -Out $thresholdCtPath
Invoke-Abe decrypt -Pub $publicPath -Sk (Join-Path $art "sk_D_F.json") -In $thresholdCtPath -Out (Join-Path $art "out_D_F.txt")
Assert-TextEquals -ExpectedPath $messagePath -ActualPath (Join-Path $art "out_D_F.txt") -Message "Pairing scenario 6 failed: {D,F} should satisfy 2-of-3."

Invoke-Abe keygen -Pub $publicPath -Msk $masterPath -OutDir $art -Attrs "D"
try {
    Invoke-Abe decrypt -Pub $publicPath -Sk (Join-Path $art "sk_D.json") -In $thresholdCtPath -Out (Join-Path $art "out_D.txt")
    throw "Pairing scenario 6 failed: {D} should be rejected by 2-of-3."
} catch {
    if ($_.Exception.Message -notmatch "Attributes do not satisfy") {
        throw "Pairing scenario 6 failed: unexpected error: $($_.Exception.Message)"
    }
}
Write-Host "Pairing scenario 6 OK: 2-of-3 threshold behavior is correct."

# Scenario 7: repeated attributes in different LSSS rows are supported.
$duplicatePolicyPath = Join-Path $art "policy_duplicate_attr.json"
$duplicateCtPath = Join-Path $art "ct_duplicate_attr.json"
[pscustomobject]@{
    k = 2
    children = @(
        [pscustomobject]@{ attr = "X" },
        [pscustomobject]@{ attr = "X" }
    )
} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $duplicatePolicyPath -Encoding UTF8
Invoke-Abe keygen -Pub $publicPath -Msk $masterPath -OutDir $art -Attrs "X"
Invoke-Abe encrypt -Pub $publicPath -Policy $duplicatePolicyPath -In $messagePath -Out $duplicateCtPath
Invoke-Abe decrypt -Pub $publicPath -Sk (Join-Path $art "sk_X.json") -In $duplicateCtPath -Out (Join-Path $art "out_X_duplicate.txt")
Assert-TextEquals -ExpectedPath $messagePath -ActualPath (Join-Path $art "out_X_duplicate.txt") -Message "Pairing scenario 7 failed: repeated attribute should decrypt."
Write-Host "Pairing scenario 7 OK: repeated attribute rows decrypted successfully."

# Scenario 8: invalid policies are rejected before encryption.
$invalidPolicies = @(
    [pscustomobject]@{
        Name = "k0"
        Policy = [pscustomobject]@{
            k = 0
            children = @([pscustomobject]@{ attr = "Z" })
        }
    },
    [pscustomobject]@{
        Name = "k_too_large"
        Policy = [pscustomobject]@{
            k = 3
            children = @(
                [pscustomobject]@{ attr = "Y" },
                [pscustomobject]@{ attr = "Z" }
            )
        }
    },
    [pscustomobject]@{
        Name = "missing_k"
        Policy = [pscustomobject]@{
            children = @([pscustomobject]@{ attr = "Z" })
        }
    },
    [pscustomobject]@{
        Name = "empty_children"
        Policy = [pscustomobject]@{
            k = 1
            children = @()
        }
    },
    [pscustomobject]@{
        Name = "empty_attr"
        Policy = [pscustomobject]@{
            attr = ""
        }
    },
    [pscustomobject]@{
        Name = "leaf_with_children"
        Policy = [pscustomobject]@{
            attr = "Q"
            children = @([pscustomobject]@{ attr = "R" })
        }
    }
)
$rejected = 0
foreach ($case in $invalidPolicies) {
    $invalidPolicyPath = Join-Path $art "policy_invalid_$($case.Name).json"
    $case.Policy | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $invalidPolicyPath -Encoding UTF8
    try {
        Invoke-Abe encrypt -Pub $publicPath -Policy $invalidPolicyPath -In $messagePath -Out (Join-Path $art "ct_invalid.json")
        throw "Invalid policy should not encrypt: $invalidPolicyPath"
    } catch {
        if ($_.Exception.Message -notmatch "Invalid policy") {
            throw "Pairing scenario 8 failed: unexpected error: $($_.Exception.Message)"
        }
        $rejected++
    }
}
if ($rejected -ne $invalidPolicies.Count) { throw "Pairing scenario 8 failed: not all invalid policies were rejected." }
Write-Host "Pairing scenario 8 OK: invalid policies correctly rejected."

Write-Host "All pairing smoke tests passed."
