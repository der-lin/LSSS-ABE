$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$bin = Join-Path $root "bin\lsss-abe.ps1"

$art = Join-Path $PSScriptRoot "artifacts"
if (Test-Path -LiteralPath $art) { Remove-Item -Recurse -Force -LiteralPath $art }
New-Item -ItemType Directory -Path $art | Out-Null

& $bin setup -OutDir $art

# Scenario 1: S1 = {A,B} satisfies (A AND B) OR C -> should succeed
& $bin keygen -Pub (Join-Path $art "public.json") -Msk (Join-Path $art "master.json") -OutDir $art -Attrs "A,B"
& $bin encrypt -Pub (Join-Path $art "public.json") -Policy (Join-Path $root "examples\policy.json") -In (Join-Path $root "examples\message.txt") -Out (Join-Path $art "ct.json")
& $bin decrypt -Pub (Join-Path $art "public.json") -Sk (Join-Path $art "sk_A_B.json") -In (Join-Path $art "ct.json") -Out (Join-Path $art "out_A_B.txt")

$orig = Get-Content -Raw -LiteralPath (Join-Path $root "examples\message.txt") -Encoding UTF8
$out1 = Get-Content -Raw -LiteralPath (Join-Path $art "out_A_B.txt") -Encoding UTF8
if ($orig -ne $out1) { throw "Scenario 1 failed: {A,B} should decrypt successfully." }
Write-Host "Scenario 1 OK: {A,B} decrypted successfully."

# Scenario 2: S2 = {C} satisfies (A AND B) OR C -> should succeed
& $bin keygen -Pub (Join-Path $art "public.json") -Msk (Join-Path $art "master.json") -OutDir $art -Attrs "C"
& $bin decrypt -Pub (Join-Path $art "public.json") -Sk (Join-Path $art "sk_C.json") -In (Join-Path $art "ct.json") -Out (Join-Path $art "out_C.txt")

$out2 = Get-Content -Raw -LiteralPath (Join-Path $art "out_C.txt") -Encoding UTF8
if ($orig -ne $out2) { throw "Scenario 2 failed: {C} should decrypt successfully." }
Write-Host "Scenario 2 OK: {C} decrypted successfully."

# Scenario 3: S3 = {A} does NOT satisfy (A AND B) OR C -> should fail
& $bin keygen -Pub (Join-Path $art "public.json") -Msk (Join-Path $art "master.json") -OutDir $art -Attrs "A"
try {
    & $bin decrypt -Pub (Join-Path $art "public.json") -Sk (Join-Path $art "sk_A.json") -In (Join-Path $art "ct.json") -Out (Join-Path $art "out_A.txt")
    throw "Scenario 3 failed: {A} should NOT be able to decrypt."
} catch {
    if ($_.Exception.Message -notmatch "Attributes do not satisfy") {
        throw "Scenario 3 failed: unexpected error: $($_.Exception.Message)"
    }
Write-Host "Scenario 3 OK: {A} correctly rejected."
}

# Scenario 4: attribute names may contain filename-unsafe characters.
$specialPolicyPath = Join-Path $art "policy_special.json"
$specialCtPath = Join-Path $art "ct_special.json"
$specialOutPath = Join-Path $art "out_role_admin.txt"
[pscustomobject]@{ attr = "role:admin" } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $specialPolicyPath -Encoding UTF8
& $bin keygen -Pub (Join-Path $art "public.json") -Msk (Join-Path $art "master.json") -OutDir $art -Attrs "role:admin"
$specialSkPath = Join-Path $art "sk_role_admin.json"
if (-not (Test-Path -LiteralPath $specialSkPath)) {
    throw "Scenario 4 failed: filename-safe secret key was not created for role:admin."
}
if (Test-Path -LiteralPath (Join-Path $art "sk_role")) {
    throw "Scenario 4 failed: unsafe attribute name produced unexpected sk_role file."
}
& $bin encrypt -Pub (Join-Path $art "public.json") -Policy $specialPolicyPath -In (Join-Path $root "examples\message.txt") -Out $specialCtPath
& $bin decrypt -Pub (Join-Path $art "public.json") -Sk $specialSkPath -In $specialCtPath -Out $specialOutPath
$outSpecial = Get-Content -Raw -LiteralPath $specialOutPath -Encoding UTF8
if ($orig -ne $outSpecial) { throw "Scenario 4 failed: role:admin should decrypt successfully." }
Write-Host "Scenario 4 OK: filename-safe attribute key for role:admin decrypted successfully."

# Scenario 5: tampering with the authenticated payload should be rejected.
$tamperedCtPath = Join-Path $art "ct_tampered.json"
$ctObj = Get-Content -Raw -LiteralPath (Join-Path $art "ct.json") -Encoding UTF8 | ConvertFrom-Json
$ctObj.payload.tag = [Convert]::ToBase64String((New-Object byte[] 32))
$ctObj | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $tamperedCtPath -Encoding UTF8
try {
    & $bin decrypt -Pub (Join-Path $art "public.json") -Sk (Join-Path $art "sk_A_B.json") -In $tamperedCtPath -Out (Join-Path $art "out_tampered.txt")
    throw "Scenario 5 failed: tampered ciphertext should NOT decrypt."
} catch {
    if ($_.Exception.Message -notmatch "Invalid ciphertext tag") {
        throw "Scenario 5 failed: unexpected error: $($_.Exception.Message)"
    }
    Write-Host "Scenario 5 OK: tampered ciphertext correctly rejected."
}

# Scenario 6: a general 2-of-3 threshold gate should accept any two matching attributes.
$thresholdPolicyPath = Join-Path $art "policy_2of3.json"
$thresholdCtPath = Join-Path $art "ct_2of3.json"
$thresholdOutPath = Join-Path $art "out_D_F.txt"
[pscustomobject]@{
    k = 2
    children = @(
        [pscustomobject]@{ attr = "D" },
        [pscustomobject]@{ attr = "E" },
        [pscustomobject]@{ attr = "F" }
    )
} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $thresholdPolicyPath -Encoding UTF8
& $bin keygen -Pub (Join-Path $art "public.json") -Msk (Join-Path $art "master.json") -OutDir $art -Attrs "D,F"
& $bin encrypt -Pub (Join-Path $art "public.json") -Policy $thresholdPolicyPath -In (Join-Path $root "examples\message.txt") -Out $thresholdCtPath
& $bin decrypt -Pub (Join-Path $art "public.json") -Sk (Join-Path $art "sk_D_F.json") -In $thresholdCtPath -Out $thresholdOutPath
$outThreshold = Get-Content -Raw -LiteralPath $thresholdOutPath -Encoding UTF8
if ($orig -ne $outThreshold) { throw "Scenario 6 failed: {D,F} should satisfy 2-of-3 policy." }
Write-Host "Scenario 6 OK: {D,F} satisfied 2-of-3 threshold policy."

# Scenario 7: a single attribute must not satisfy the 2-of-3 threshold gate.
& $bin keygen -Pub (Join-Path $art "public.json") -Msk (Join-Path $art "master.json") -OutDir $art -Attrs "D"
try {
    & $bin decrypt -Pub (Join-Path $art "public.json") -Sk (Join-Path $art "sk_D.json") -In $thresholdCtPath -Out (Join-Path $art "out_D.txt")
    throw "Scenario 7 failed: {D} should NOT satisfy 2-of-3 policy."
} catch {
    if ($_.Exception.Message -notmatch "Attributes do not satisfy") {
        throw "Scenario 7 failed: unexpected error: $($_.Exception.Message)"
    }
    Write-Host "Scenario 7 OK: {D} correctly rejected by 2-of-3 threshold policy."
}

# Scenario 8: repeated attributes in different rows should be supported.
$duplicatePolicyPath = Join-Path $art "policy_duplicate_attr.json"
$duplicateCtPath = Join-Path $art "ct_duplicate_attr.json"
$duplicateOutPath = Join-Path $art "out_X_duplicate.txt"
[pscustomobject]@{
    k = 2
    children = @(
        [pscustomobject]@{ attr = "X" },
        [pscustomobject]@{ attr = "X" }
    )
} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $duplicatePolicyPath -Encoding UTF8
& $bin keygen -Pub (Join-Path $art "public.json") -Msk (Join-Path $art "master.json") -OutDir $art -Attrs "X"
& $bin encrypt -Pub (Join-Path $art "public.json") -Policy $duplicatePolicyPath -In (Join-Path $root "examples\message.txt") -Out $duplicateCtPath
& $bin decrypt -Pub (Join-Path $art "public.json") -Sk (Join-Path $art "sk_X.json") -In $duplicateCtPath -Out $duplicateOutPath
$outDuplicate = Get-Content -Raw -LiteralPath $duplicateOutPath -Encoding UTF8
if ($orig -ne $outDuplicate) { throw "Scenario 8 failed: repeated attribute rows should decrypt with attribute X." }
Write-Host "Scenario 8 OK: repeated attribute rows decrypted successfully."

# Scenario 9: invalid policies should be rejected before encryption.
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
$invalidPoliciesRejected = 0
foreach ($case in $invalidPolicies) {
    $invalidPolicyPath = Join-Path $art "policy_invalid_$($case.Name).json"
    $case.Policy | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $invalidPolicyPath -Encoding UTF8
    try {
        & $bin encrypt -Pub (Join-Path $art "public.json") -Policy $invalidPolicyPath -In (Join-Path $root "examples\message.txt") -Out (Join-Path $art "ct_invalid.json")
        throw "Invalid policy should not encrypt: $invalidPolicyPath"
    } catch {
        if ($_.Exception.Message -notmatch "Invalid policy") {
            throw "Scenario 9 failed: unexpected error for invalid policy: $($_.Exception.Message)"
        }
        $invalidPoliciesRejected++
    }
}
if ($invalidPoliciesRejected -ne $invalidPolicies.Count) { throw "Scenario 9 failed: not all invalid policies were rejected." }
Write-Host "Scenario 9 OK: invalid policies correctly rejected."

Write-Host "All smoke tests passed."
