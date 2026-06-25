function Invoke-LsssAbeMod {
    param(
        [Parameter(Mandatory)][System.Numerics.BigInteger]$x,
        [Parameter(Mandatory)][System.Numerics.BigInteger]$p
    )

    $r = $x % $p
    if ($r -lt 0) { $r += $p }
    $r
}

function Get-LsssAbePrime {
    [System.Numerics.BigInteger]::Parse("170141183460469231731687303715884105727")
}

function Get-LsssAbeRngBytes {
    param([Parameter(Mandatory)][int]$Count)

    $bytes = New-Object byte[] $Count
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    $bytes
}

function New-LsssAbeRandomZp {
    param([Parameter(Mandatory)][System.Numerics.BigInteger]$p)

    $bytes = Get-LsssAbeRngBytes -Count 64
    $x = [System.Numerics.BigInteger]::new($bytes)
    Invoke-LsssAbeMod -x $x -p $p
}

function New-LsssAbeHashZp {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][System.Numerics.BigInteger]$p
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $h = $sha.ComputeHash($bytes)
    $sha.Dispose()
    $x = [System.Numerics.BigInteger]::new($h)
    Invoke-LsssAbeMod -x $x -p $p
}

function New-LsssAbeHashBytes {
    param([Parameter(Mandatory)][byte[]]$Bytes)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    $h = $sha.ComputeHash($Bytes)
    $sha.Dispose()
    $h
}

function New-LsssAbeExponentGroupAdapter {
    param([Parameter(Mandatory)][System.Numerics.BigInteger]$p)

    [pscustomobject]@{
        name = "ExponentSimulation"
        scalarModulus = $p
        supportsRealPairing = $false
    }
}

function New-LsssAbePairingGroupAdapter {
    param(
        [Parameter(Mandatory)][string]$Library,
        [Parameter(Mandatory)][string]$Curve
    )

    throw "Real PairingAdapter is not implemented. Connect a pairing library that provides G1/G2/GT/Zp, pair, hash-to-group, serialization, and subgroup checks. Requested: $Library / $Curve."
}

function ConvertTo-LsssAbeGroupMetadata {
    param([Parameter(Mandatory)][object]$Group)

    [pscustomobject]@{
        adapter = [string]$Group.name
        scalar_modulus = ([System.Numerics.BigInteger]$Group.scalarModulus).ToString()
        real_pairing = [bool]$Group.supportsRealPairing
        migration_target = "PairingAdapter(G1,G2,GT,Zp,pair,hash,serialize,subgroup-check)"
    }
}

function Get-LsssAbeGroupAdapterFromPublic {
    param([Parameter(Mandatory)][object]$Public)

    $p = [System.Numerics.BigInteger]::Parse([string]$Public.p)
    if ($null -ne $Public.group) {
        $adapterName = [string]$Public.group.adapter
        if ($adapterName -and $adapterName -ne "ExponentSimulation") {
            throw "Public key requires group adapter '$adapterName', but the current experimental build only implements ExponentSimulation."
        }

        $metadataModulus = [string]$Public.group.scalar_modulus
        if ($metadataModulus -and $metadataModulus -ne $p.ToString()) {
            throw "Public key group metadata does not match public modulus p."
        }
    }

    New-LsssAbeExponentGroupAdapter -p $p
}

function Assert-LsssAbeExponentGroupAdapter {
    param([Parameter(Mandatory)][object]$Group)

    if ([string]$Group.name -ne "ExponentSimulation") {
        throw "Unsupported group adapter '$($Group.name)' in the current experimental implementation."
    }
}

function Invoke-LsssAbeGroupMod {
    param(
        [Parameter(Mandatory)][object]$Group,
        [Parameter(Mandatory)][System.Numerics.BigInteger]$x
    )

    Assert-LsssAbeExponentGroupAdapter -Group $Group
    Invoke-LsssAbeMod -x $x -p ([System.Numerics.BigInteger]$Group.scalarModulus)
}

function New-LsssAbeGroupRandomScalar {
    param([Parameter(Mandatory)][object]$Group)

    Assert-LsssAbeExponentGroupAdapter -Group $Group
    New-LsssAbeRandomZp -p ([System.Numerics.BigInteger]$Group.scalarModulus)
}

function New-LsssAbeGroupHashAttribute {
    param(
        [Parameter(Mandatory)][object]$Group,
        [Parameter(Mandatory)][string]$Text
    )

    Assert-LsssAbeExponentGroupAdapter -Group $Group
    New-LsssAbeHashZp -Text $Text -p ([System.Numerics.BigInteger]$Group.scalarModulus)
}

function Invoke-LsssAbeGroupAdd {
    param(
        [Parameter(Mandatory)][object]$Group,
        [Parameter(Mandatory)][System.Numerics.BigInteger]$a,
        [Parameter(Mandatory)][System.Numerics.BigInteger]$b
    )

    Invoke-LsssAbeGroupMod -Group $Group -x ($a + $b)
}

function Invoke-LsssAbeGroupSub {
    param(
        [Parameter(Mandatory)][object]$Group,
        [Parameter(Mandatory)][System.Numerics.BigInteger]$a,
        [Parameter(Mandatory)][System.Numerics.BigInteger]$b
    )

    Invoke-LsssAbeGroupMod -Group $Group -x ($a - $b)
}

function Invoke-LsssAbeGroupMul {
    param(
        [Parameter(Mandatory)][object]$Group,
        [Parameter(Mandatory)][System.Numerics.BigInteger]$a,
        [Parameter(Mandatory)][System.Numerics.BigInteger]$b
    )

    Invoke-LsssAbeGroupMod -Group $Group -x ($a * $b)
}

function Invoke-LsssAbeGroupPair {
    param(
        [Parameter(Mandatory)][object]$Group,
        [Parameter(Mandatory)][System.Numerics.BigInteger]$Left,
        [Parameter(Mandatory)][System.Numerics.BigInteger]$Right
    )

    Invoke-LsssAbeGroupMul -Group $Group -a $Left -b $Right
}

function New-LsssAbeAesCbcHmacEncrypt {
    param(
        [Parameter(Mandatory)][byte[]]$Key32,
        [Parameter(Mandatory)][byte[]]$PlainBytes
    )

    $iv = Get-LsssAbeRngBytes -Count 16
    $encKey = New-LsssAbeHashBytes -Bytes ($Key32 + [System.Text.Encoding]::UTF8.GetBytes("AES"))
    $macKey = New-LsssAbeHashBytes -Bytes ($Key32 + [System.Text.Encoding]::UTF8.GetBytes("HMAC"))
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $encKey
    $aes.IV = $iv
    $enc = $aes.CreateEncryptor()
    $cipher = $enc.TransformFinalBlock($PlainBytes, 0, $PlainBytes.Length)
    $enc.Dispose()
    $aes.Dispose()
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($macKey)
    $macInput = New-Object byte[] ($iv.Length + $cipher.Length)
    [System.Array]::Copy($iv, 0, $macInput, 0, $iv.Length)
    [System.Array]::Copy($cipher, 0, $macInput, $iv.Length, $cipher.Length)
    $tag = $hmac.ComputeHash($macInput)
    $hmac.Dispose()
    @{
        nonce = [Convert]::ToBase64String($iv)
        tag   = [Convert]::ToBase64String($tag)
        data  = [Convert]::ToBase64String($cipher)
    }
}

function New-LsssAbeAesCbcHmacDecrypt {
    param(
        [Parameter(Mandatory)][byte[]]$Key32,
        [Parameter(Mandatory)]$Payload
    )

    $iv = [Convert]::FromBase64String($Payload.nonce)
    $tag = [Convert]::FromBase64String($Payload.tag)
    $cipher = [Convert]::FromBase64String($Payload.data)
    $encKey = New-LsssAbeHashBytes -Bytes ($Key32 + [System.Text.Encoding]::UTF8.GetBytes("AES"))
    $macKey = New-LsssAbeHashBytes -Bytes ($Key32 + [System.Text.Encoding]::UTF8.GetBytes("HMAC"))
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($macKey)
    $macInput = New-Object byte[] ($iv.Length + $cipher.Length)
    [System.Array]::Copy($iv, 0, $macInput, 0, $iv.Length)
    [System.Array]::Copy($cipher, 0, $macInput, $iv.Length, $cipher.Length)
    $expect = $hmac.ComputeHash($macInput)
    $hmac.Dispose()
    if (-not [System.Linq.Enumerable]::SequenceEqual($expect, $tag)) { throw "Invalid ciphertext tag." }
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $encKey
    $aes.IV = $iv
    $dec = $aes.CreateDecryptor()
    $plain = $dec.TransformFinalBlock($cipher, 0, $cipher.Length)
    $dec.Dispose()
    $aes.Dispose()
    $plain
}

function Get-LsssAbeProp {
    param(
        [Parameter(Mandatory)]$Obj,
        [Parameter(Mandatory)][string]$Name
    )
    $p = $Obj.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    $p.Value
}

function Assert-LsssAbePolicyNode {
    param([Parameter(Mandatory)][AllowNull()][object]$Node)

    if ($null -eq $Node) { throw "Invalid policy node: node must not be null." }

    $attr = Get-LsssAbeProp -Obj $Node -Name "attr"
    $childrenValue = Get-LsssAbeProp -Obj $Node -Name "children"

    if ($null -ne $attr) {
        if (-not ($attr -is [string])) { throw "Invalid policy leaf: attr must be a string." }
        if ([string]::IsNullOrWhiteSpace([string]$attr)) { throw "Invalid policy leaf: attr must not be empty." }
        if ($null -ne $childrenValue) { throw "Invalid policy node: leaf must not also define children." }
        return
    }

    $kValue = Get-LsssAbeProp -Obj $Node -Name "k"
    if ($null -eq $kValue) { throw "Invalid policy gate: missing k." }
    if ($null -eq $childrenValue) { throw "Invalid policy gate: missing children." }

    $children = @($childrenValue)
    if ($children.Length -lt 1) { throw "Invalid policy gate: children must not be empty." }

    if (-not ($kValue -is [byte] -or $kValue -is [int16] -or $kValue -is [int32] -or $kValue -is [int64])) {
        throw "Invalid policy gate: k must be an integer."
    }
    try {
        $k = [int]$kValue
    } catch {
        throw "Invalid policy gate: k is outside supported range."
    }
    if ($k -lt 1) { throw "Invalid policy gate: k must be at least 1." }
    if ($k -gt $children.Length) { throw "Invalid policy gate: k must not exceed child count." }

    foreach ($c in $children) { Assert-LsssAbePolicyNode -Node $c }
}

function New-LsssAbeVecZeros {
    param([Parameter(Mandatory)][int]$Len)
    $v = New-Object 'System.Numerics.BigInteger[]' $Len
    for ($i = 0; $i -lt $Len; $i++) { $v[$i] = [System.Numerics.BigInteger]::Zero }
    ,$v
}

function New-LsssAbeVecUnit {
    param(
        [Parameter(Mandatory)][int]$Len,
        [Parameter(Mandatory)][int]$Index,
        [Parameter(Mandatory)][System.Numerics.BigInteger]$p
    )

    $v = New-LsssAbeVecZeros -Len $Len
    $v[$Index] = Invoke-LsssAbeMod -x ([System.Numerics.BigInteger]::One) -p $p
    $v
}

function Invoke-LsssAbeVecAdd {
    param(
        [Parameter(Mandatory)][System.Numerics.BigInteger[]]$a,
        [Parameter(Mandatory)][System.Numerics.BigInteger[]]$b,
        [Parameter(Mandatory)][System.Numerics.BigInteger]$p
    )

    $n = $a.Length
    $r = New-Object 'System.Numerics.BigInteger[]' $n
    for ($i = 0; $i -lt $n; $i++) {
        $r[$i] = Invoke-LsssAbeMod -x ($a[$i] + $b[$i]) -p $p
    }
    ,$r
}

function Invoke-LsssAbeVecScale {
    param(
        [Parameter(Mandatory)][System.Numerics.BigInteger[]]$v,
        [Parameter(Mandatory)][System.Numerics.BigInteger]$k,
        [Parameter(Mandatory)][System.Numerics.BigInteger]$p
    )

    $n = $v.Length
    $r = New-Object 'System.Numerics.BigInteger[]' $n
    for ($i = 0; $i -lt $n; $i++) {
        $r[$i] = Invoke-LsssAbeMod -x ($v[$i] * $k) -p $p
    }
    ,$r
}

function Invoke-LsssAbeVecDot {
    param(
        [Parameter(Mandatory)][System.Numerics.BigInteger[]]$a,
        [Parameter(Mandatory)][System.Numerics.BigInteger[]]$b,
        [Parameter(Mandatory)][System.Numerics.BigInteger]$p
    )

    $n = $a.Length
    $acc = [System.Numerics.BigInteger]::Zero
    for ($i = 0; $i -lt $n; $i++) {
        $acc = Invoke-LsssAbeMod -x ($acc + ($a[$i] * $b[$i])) -p $p
    }
    $acc
}

function Invoke-LsssAbePowZp {
    param(
        [Parameter(Mandatory)][System.Numerics.BigInteger]$x,
        [Parameter(Mandatory)][System.Numerics.BigInteger]$e,
        [Parameter(Mandatory)][System.Numerics.BigInteger]$p
    )

    $result = [System.Numerics.BigInteger]::One
    $base = Invoke-LsssAbeMod -x $x -p $p
    $exp = $e
    while ($exp -gt 0) {
        if (($exp % 2) -eq 1) { $result = Invoke-LsssAbeMod -x ($result * $base) -p $p }
        $base = Invoke-LsssAbeMod -x ($base * $base) -p $p
        $exp = [System.Numerics.BigInteger]::op_RightShift($exp, 1)
    }
    $result
}

function Invoke-LsssAbeInvZp {
    param(
        [Parameter(Mandatory)][System.Numerics.BigInteger]$x,
        [Parameter(Mandatory)][System.Numerics.BigInteger]$p
    )

    Invoke-LsssAbePowZp -x $x -e ($p - 2) -p $p
}

function ConvertFrom-LsssAbeJsonFile {
    param([Parameter(Mandatory)][string]$Path)
    $raw = Get-Content -Raw -LiteralPath $Path -Encoding UTF8
    $cmd = Get-Command ConvertFrom-Json
    if ($cmd.Parameters.ContainsKey("Depth")) { return ($raw | ConvertFrom-Json -Depth 100) }
    $raw | ConvertFrom-Json
}

function ConvertTo-LsssAbeJsonFile {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string]$Path
    )

    $cmd = Get-Command ConvertTo-Json
    if ($cmd.Parameters.ContainsKey("Depth")) { $json = $Object | ConvertTo-Json -Depth 100 } else { $json = $Object | ConvertTo-Json }
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
}

function New-LsssAbePolicyLeaf {
    param([Parameter(Mandatory)][string]$Attr)
    [pscustomobject]@{ attr = $Attr }
}

function New-LsssAbePolicyNode {
    param(
        [Parameter(Mandatory)][int]$k,
        [Parameter(Mandatory)][object[]]$children
    )
    [pscustomobject]@{ k = $k; children = $children }
}

function Get-LsssAbePolicyLeaves {
    param([Parameter(Mandatory)][object]$Node)

    $attr = Get-LsssAbeProp -Obj $Node -Name "attr"
    if ($null -ne $attr) { return @([string]$attr) }
    $acc = @()
    foreach ($c in (Get-LsssAbeProp -Obj $Node -Name "children")) { $acc += Get-LsssAbePolicyLeaves -Node $c }
    $acc
}

function Get-LsssAbeGateRandomCount {
    param([Parameter(Mandatory)][object]$Node)

    $attr = Get-LsssAbeProp -Obj $Node -Name "attr"
    if ($null -ne $attr) { return 0 }
    $k = [int](Get-LsssAbeProp -Obj $Node -Name "k")
    if ($k -lt 1) { throw "Invalid k in gate." }
    $sum = $k - 1
    foreach ($c in (Get-LsssAbeProp -Obj $Node -Name "children")) { $sum += Get-LsssAbeGateRandomCount -Node $c }
    $sum
}

function New-LsssAbeGateIndexMap {
    param(
        [Parameter(Mandatory)][object]$Node,
        [Parameter(Mandatory)][ref]$NextIndex,
        [Parameter(Mandatory)][hashtable]$Map
    )

    $attr = Get-LsssAbeProp -Obj $Node -Name "attr"
    if ($null -ne $attr) { return }
    $k = [int](Get-LsssAbeProp -Obj $Node -Name "k")
    $indices = @()
    for ($j = 1; $j -le ($k - 1); $j++) {
        $indices += $NextIndex.Value
        $NextIndex.Value++
    }
    $Map[[System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($Node)] = $indices
    foreach ($c in (Get-LsssAbeProp -Obj $Node -Name "children")) { New-LsssAbeGateIndexMap -Node $c -NextIndex $NextIndex -Map $Map }
}

function ConvertTo-LsssAbeLsssFromPolicy {
    param(
        [Parameter(Mandatory)][object]$PolicyTree,
        [Parameter(Mandatory)][System.Numerics.BigInteger]$p
    )

    Assert-LsssAbePolicyNode -Node $PolicyTree

    $randomCount = Get-LsssAbeGateRandomCount -Node $PolicyTree
    $n = 1 + $randomCount
    $indexMap = @{}
    $next = 1
    New-LsssAbeGateIndexMap -Node $PolicyTree -NextIndex ([ref]$next) -Map $indexMap

    $rows = New-Object System.Collections.Generic.List[object]

    $rootShare = New-LsssAbeVecZeros -Len $n
    $rootShare[0] = [System.Numerics.BigInteger]::One

    function Visit {
        param(
            [Parameter(Mandatory)][object]$Node,
            [Parameter(Mandatory)][System.Numerics.BigInteger[]]$ShareVec
        )

        $attr = Get-LsssAbeProp -Obj $Node -Name "attr"
        if ($null -ne $attr) {
            $rows.Add([pscustomobject]@{ attr = [string]$attr; row = $ShareVec })
            return
        }

        $k = [int](Get-LsssAbeProp -Obj $Node -Name "k")
        $children = @((Get-LsssAbeProp -Obj $Node -Name "children"))
        $gateKey = [System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($Node)
        $gateRandIndices = @($indexMap[$gateKey])

        $coeffs = New-Object System.Collections.Generic.List[object]
        $coeffs.Add($ShareVec)
        for ($j = 1; $j -le ($k - 1); $j++) {
            $coeffs.Add((New-LsssAbeVecUnit -Len $n -Index $gateRandIndices[$j - 1] -p $p))
        }

        for ($i = 0; $i -lt $children.Length; $i++) {
            $t = [System.Numerics.BigInteger]($i + 1)
            $childShare = New-LsssAbeVecZeros -Len $n
            for ($j = 0; $j -le ($k - 1); $j++) {
                $pow = Invoke-LsssAbePowZp -x $t -e ([System.Numerics.BigInteger]$j) -p $p
                $term = Invoke-LsssAbeVecScale -v $coeffs[$j] -k $pow -p $p
                $childShare = Invoke-LsssAbeVecAdd -a $childShare -b $term -p $p
            }
            Visit -Node $children[$i] -ShareVec $childShare
        }
    }

    Visit -Node $PolicyTree -ShareVec $rootShare

    $M = @()
    $rho = @()
    foreach ($r in $rows) {
        $M += ,$r.row
        $rho += $r.attr
    }

    [pscustomobject]@{
        n = $n
        l = $M.Length
        M = $M
        rho = $rho
    }
}

function Solve-LsssAbeWeights {
    param(
        [Parameter(Mandatory)][System.Numerics.BigInteger[][]]$M,
        [Parameter(Mandatory)][string[]]$rho,
        [Parameter(Mandatory)][string[]]$Attrs,
        [Parameter(Mandatory)][System.Numerics.BigInteger]$p
    )

    $rowIndicesList = New-Object System.Collections.Generic.List[int]
    for ($rowIdx = 0; $rowIdx -lt $rho.Length; $rowIdx++) {
        if ($Attrs -contains $rho[$rowIdx]) { $rowIndicesList.Add($rowIdx) }
    }
    if ($rowIndicesList.Count -eq 0) { return $null }

    $n = $M[0].Length
    $l = $rowIndicesList.Count

    $A = New-Object 'System.Numerics.BigInteger[][]' $n
    for ($r = 0; $r -lt $n; $r++) {
        $row = New-Object 'System.Numerics.BigInteger[]' ($l + 1)
        for ($c = 0; $c -lt $l; $c++) {
            $rowIndex = $rowIndicesList[$c]
            $row[$c] = Invoke-LsssAbeMod -x ($M[$rowIndex][$r]) -p $p
        }
        $row[$l] = if ($r -eq 0) { [System.Numerics.BigInteger]::One } else { [System.Numerics.BigInteger]::Zero }
        $A[$r] = $row
    }

    $pivotRow = 0
    $pivotColForRow = @{}
    $rowForPivotCol = @{}

    for ($col = 0; $col -lt $l; $col++) {
        $sel = -1
        for ($r = $pivotRow; $r -lt $n; $r++) {
            if ($A[$r][$col] -ne 0) { $sel = $r; break }
        }
        if ($sel -eq -1) { continue }
        if ($sel -ne $pivotRow) {
            $tmp = $A[$sel]
            $A[$sel] = $A[$pivotRow]
            $A[$pivotRow] = $tmp
        }
        $inv = Invoke-LsssAbeInvZp -x $A[$pivotRow][$col] -p $p
        for ($c = $col; $c -le $l; $c++) {
            $A[$pivotRow][$c] = Invoke-LsssAbeMod -x ($A[$pivotRow][$c] * $inv) -p $p
        }
        for ($r = 0; $r -lt $n; $r++) {
            if ($r -eq $pivotRow) { continue }
            $factor = $A[$r][$col]
            if ($factor -eq 0) { continue }
            for ($c = $col; $c -le $l; $c++) {
                $A[$r][$c] = Invoke-LsssAbeMod -x ($A[$r][$c] - ($factor * $A[$pivotRow][$c])) -p $p
            }
        }
        $pivotColForRow[$pivotRow] = $col
        $rowForPivotCol[$col] = $pivotRow
        $pivotRow++
        if ($pivotRow -ge $n) { break }
    }

    for ($r = 0; $r -lt $n; $r++) {
        $allZero = $true
        for ($c = 0; $c -lt $l; $c++) {
            if ($A[$r][$c] -ne 0) { $allZero = $false; break }
        }
        if ($allZero -and ($A[$r][$l] -ne 0)) { return $null }
    }

    $x = New-Object 'System.Numerics.BigInteger[]' $l
    for ($i = 0; $i -lt $l; $i++) { $x[$i] = [System.Numerics.BigInteger]::Zero }

    foreach ($kv in $pivotColForRow.GetEnumerator()) {
        $r = [int]$kv.Key
        $c = [int]$kv.Value
        $x[$c] = Invoke-LsssAbeMod -x $A[$r][$l] -p $p
    }

    @{
        indices = @($rowIndicesList)
        omega = $x
    }
}

function New-LsssAbeSetup {
    $p = Get-LsssAbePrime
    $group = New-LsssAbeExponentGroupAdapter -p $p
    $alpha = New-LsssAbeGroupRandomScalar -Group $group
    $a = New-LsssAbeGroupRandomScalar -Group $group
    $pub = [pscustomobject]@{
        p = $p.ToString()
        g = "1"
        ga = $a.ToString()
        egg_alpha = $alpha.ToString()
        group = ConvertTo-LsssAbeGroupMetadata -Group $group
    }
    $msk = [pscustomobject]@{
        alpha = $alpha.ToString()
        a = $a.ToString()
    }
    @{ public = $pub; master = $msk }
}

function New-LsssAbeKeyGen {
    param(
        [Parameter(Mandatory)][object]$Public,
        [Parameter(Mandatory)][object]$Master,
        [Parameter(Mandatory)][string[]]$Attrs
    )

    $group = Get-LsssAbeGroupAdapterFromPublic -Public $Public
    $p = [System.Numerics.BigInteger]$group.scalarModulus
    $a = [System.Numerics.BigInteger]::Parse([string]$Master.a)
    $alpha = [System.Numerics.BigInteger]::Parse([string]$Master.alpha)

    $t = New-LsssAbeGroupRandomScalar -Group $group
    $K = Invoke-LsssAbeGroupAdd -Group $group -a $alpha -b (Invoke-LsssAbeGroupMul -Group $group -a $a -b $t)
    $L = $t

    $Kx = @{}
    foreach ($x in $Attrs) {
        $hx = New-LsssAbeGroupHashAttribute -Group $group -Text $x
        $Kx[$x] = (Invoke-LsssAbeGroupMul -Group $group -a $hx -b $t).ToString()
    }

    [pscustomobject]@{
        attrs = $Attrs
        K = $K.ToString()
        L = $L.ToString()
        Kx = $Kx
    }
}

function New-LsssAbeEncrypt {
    param(
        [Parameter(Mandatory)][object]$Public,
        [Parameter(Mandatory)][object]$PolicyTree,
        [Parameter(Mandatory)][byte[]]$PlainBytes
    )

    $group = Get-LsssAbeGroupAdapterFromPublic -Public $Public
    $p = [System.Numerics.BigInteger]$group.scalarModulus
    $a = [System.Numerics.BigInteger]::Parse([string]$Public.ga)
    $alpha = [System.Numerics.BigInteger]::Parse([string]$Public.egg_alpha)

    $lsss = ConvertTo-LsssAbeLsssFromPolicy -PolicyTree $PolicyTree -p $p
    $M = $lsss.M
    $rho = $lsss.rho
    $n = [int]$lsss.n
    $l = [int]$lsss.l

    $s = New-LsssAbeGroupRandomScalar -Group $group
    $v = New-Object 'System.Numerics.BigInteger[]' $n
    $u = New-Object 'System.Numerics.BigInteger[]' $n
    $v[0] = $s
    $u[0] = [System.Numerics.BigInteger]::Zero
    for ($j = 1; $j -lt $n; $j++) {
        $v[$j] = New-LsssAbeGroupRandomScalar -Group $group
        $u[$j] = New-LsssAbeGroupRandomScalar -Group $group
    }

    $lambda = New-Object 'System.Numerics.BigInteger[]' $l
    $w = New-Object 'System.Numerics.BigInteger[]' $l
    for ($i = 0; $i -lt $l; $i++) {
        $lambda[$i] = Invoke-LsssAbeVecDot -a $M[$i] -b $v -p $p
        $w[$i] = Invoke-LsssAbeVecDot -a $M[$i] -b $u -p $p
    }

    $mExp = New-LsssAbeGroupRandomScalar -Group $group
    $mBytes = [System.Text.Encoding]::UTF8.GetBytes($mExp.ToString())
    $key = New-LsssAbeHashBytes -Bytes $mBytes
    $payload = New-LsssAbeAesCbcHmacEncrypt -Key32 $key -PlainBytes $PlainBytes

    $Cexp = Invoke-LsssAbeGroupAdd -Group $group -a $mExp -b (Invoke-LsssAbeGroupMul -Group $group -a $alpha -b $s)
    $C0 = $s

    $Ci = @()
    $Di = @()
    for ($i = 0; $i -lt $l; $i++) {
        $attr = [string]$rho[$i]
        $h = New-LsssAbeGroupHashAttribute -Group $group -Text $attr
        $ciLeft = Invoke-LsssAbeGroupMul -Group $group -a $a -b $lambda[$i]
        $ciRight = Invoke-LsssAbeGroupMul -Group $group -a $h -b $w[$i]
        $ciExp = Invoke-LsssAbeGroupSub -Group $group -a $ciLeft -b $ciRight
        $diExp = Invoke-LsssAbeGroupMod -Group $group -x $w[$i]
        $Ci += $ciExp.ToString()
        $Di += $diExp.ToString()
    }

    $Mstr = @()
    for ($i = 0; $i -lt $l; $i++) {
        $row = @()
        for ($j = 0; $j -lt $n; $j++) { $row += $M[$i][$j].ToString() }
        $Mstr += ,$row
    }

    [pscustomobject]@{
        policy = $PolicyTree
        lsss = [pscustomobject]@{
            M = $Mstr
            rho = $rho
        }
        C = $Cexp.ToString()
        C0 = $C0.ToString()
        Ci = $Ci
        Di = $Di
        payload = $payload
    }
}

function New-LsssAbeDecrypt {
    param(
        [Parameter(Mandatory)][object]$Public,
        [Parameter(Mandatory)][object]$SecretKey,
        [Parameter(Mandatory)][object]$Ciphertext
    )

    $group = Get-LsssAbeGroupAdapterFromPublic -Public $Public
    $p = [System.Numerics.BigInteger]$group.scalarModulus

    $keyK = [System.Numerics.BigInteger]::Parse([string]$SecretKey.K)
    $keyL = [System.Numerics.BigInteger]::Parse([string]$SecretKey.L)
    $attrs = @([string[]]$SecretKey.attrs)
    $Kx = @{}
    $kxObj = $SecretKey.Kx
    if ($kxObj -is [hashtable]) {
        foreach ($attrName in $kxObj.Keys) {
            $Kx[[string]$attrName] = [System.Numerics.BigInteger]::Parse([string]$kxObj[$attrName])
        }
    } else {
        foreach ($attrName in $kxObj.PSObject.Properties.Name) {
            $Kx[[string]$attrName] = [System.Numerics.BigInteger]::Parse([string]$kxObj.$attrName)
        }
    }

    $rho = @([string[]]$Ciphertext.lsss.rho)
    $Mraw = $Ciphertext.lsss.M
    $rowCount = $rho.Length
    $n = $Mraw[0].Count
    $M = New-Object 'System.Numerics.BigInteger[][]' $rowCount
    for ($i = 0; $i -lt $rowCount; $i++) {
        $row = New-Object 'System.Numerics.BigInteger[]' $n
        for ($j = 0; $j -lt $n; $j++) {
            $row[$j] = Invoke-LsssAbeMod -x ([System.Numerics.BigInteger]::Parse([string]$Mraw[$i][$j])) -p $p
        }
        $M[$i] = $row
    }

    $weights = Solve-LsssAbeWeights -M $M -rho $rho -Attrs $attrs -p $p
    if ($null -eq $weights) { throw "Attributes do not satisfy policy." }
    $rowIndices = @([int[]]$weights.indices)
    $omega = [System.Numerics.BigInteger[]]$weights.omega

    $Ci = @([string[]]$Ciphertext.Ci)
    $Di = @([string[]]$Ciphertext.Di)
    $C0 = [System.Numerics.BigInteger]::Parse([string]$Ciphertext.C0)
    $Cexp = [System.Numerics.BigInteger]::Parse([string]$Ciphertext.C)

    $Aexp = [System.Numerics.BigInteger]::Zero
    for ($pos = 0; $pos -lt $rowIndices.Length; $pos++) {
        $rowIndex = $rowIndices[$pos]
        $attr = [string]$rho[$rowIndex]
        if (-not $Kx.ContainsKey($attr)) { continue }
        $ciExp = [System.Numerics.BigInteger]::Parse($Ci[$rowIndex])
        $diExp = [System.Numerics.BigInteger]::Parse($Di[$rowIndex])
        $term1 = Invoke-LsssAbeGroupPair -Group $group -Left $ciExp -Right $keyL
        $term2 = Invoke-LsssAbeGroupPair -Group $group -Left $diExp -Right $Kx[$attr]
        $term = Invoke-LsssAbeGroupAdd -Group $group -a $term1 -b $term2
        $col = $pos
        $wcoef = $omega[$col]
        $Aexp = Invoke-LsssAbeGroupAdd -Group $group -a $Aexp -b (Invoke-LsssAbeGroupMul -Group $group -a $term -b $wcoef)
    }

    $eC0K = Invoke-LsssAbeGroupPair -Group $group -Left $C0 -Right $keyK
    $Bexp = Invoke-LsssAbeGroupSub -Group $group -a $eC0K -b $Aexp
    $mExp = Invoke-LsssAbeGroupSub -Group $group -a $Cexp -b $Bexp

    $mBytes = [System.Text.Encoding]::UTF8.GetBytes($mExp.ToString())
    $key = New-LsssAbeHashBytes -Bytes $mBytes
    New-LsssAbeAesCbcHmacDecrypt -Key32 $key -Payload $Ciphertext.payload
}

Export-ModuleMember -Function `
    New-LsssAbeSetup, `
    New-LsssAbeKeyGen, `
    New-LsssAbeEncrypt, `
    New-LsssAbeDecrypt, `
    ConvertFrom-LsssAbeJsonFile, `
    ConvertTo-LsssAbeJsonFile
