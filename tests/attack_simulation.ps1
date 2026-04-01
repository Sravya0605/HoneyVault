# CONFIG
$BASE_URL = "http://127.0.0.1:8000/api"

# SETTINGS
$ITERATIONS = 50
$ATTACKS_PER_VAULT = 10
$DELAY_MS = 50

function Random-String($length = 8) {
    -join ((65..90) + (48..57) | Get-Random -Count $length | ForEach-Object {[char]$_})
}

function Generate-AWSKey {
    return "AKIA" + (Random-String 16)
}

Write-Host "Starting FULL simulation..."

for ($i = 1; $i -le $ITERATIONS; $i++) {

    # -----------------------------
    # 1. Generate fresh credentials
    # -----------------------------
    $realKey = Generate-AWSKey
    $password = "pass" + (Random-String 4)

    # -----------------------------
    # 2. Encrypt (create vault)
    # -----------------------------
    $encryptBody = @{
        password = $password
        aws_api_key = $realKey
    } | ConvertTo-Json

    try {
        $encResponse = Invoke-RestMethod `
            -Uri "$BASE_URL/encrypt" `
            -Method POST `
            -Body $encryptBody `
            -ContentType "application/json"

        $vaultId = $encResponse.vault_id

        Write-Host "[VAULT CREATED] $vaultId"
    }
    catch {
        Write-Host "[ERROR] Vault creation failed"
        continue
    }

    # -----------------------------
    # 3. Attack + usage simulation
    # -----------------------------
    for ($j = 1; $j -le $ATTACKS_PER_VAULT; $j++) {

        $mode = Get-Random -Minimum 1 -Maximum 100

        # REAL decrypt (25%)
        if ($mode -le 25) {
            $body = @{
                password = $password
                vault_id = $vaultId
            } | ConvertTo-Json

            try {
                $res = Invoke-RestMethod `
                    -Uri "$BASE_URL/decrypt" `
                    -Method POST `
                    -Body $body `
                    -ContentType "application/json"

                Write-Host "[REAL DECRYPT] status=$($res.status)"
            }
            catch {
                Write-Host "[ERROR] Real decrypt failed"
            }
        }

        # WRONG password (35%)
        elseif ($mode -le 60) {
            $fakePassword = Random-String 6

            $body = @{
                password = $fakePassword
                vault_id = $vaultId
            } | ConvertTo-Json

            try {
                $res = Invoke-RestMethod `
                    -Uri "$BASE_URL/decrypt" `
                    -Method POST `
                    -Body $body `
                    -ContentType "application/json"

                Write-Host "[FAKE DECRYPT] status=$($res.status)"
            }
            catch {
                Write-Host "[ERROR] Fake decrypt failed"
            }
        }

        # REAL key usage (20%)
        elseif ($mode -le 80) {
            try {
                Invoke-RestMethod `
                    -Uri "$BASE_URL/cloud/instances" `
                    -Headers @{ "x-api-key" = $realKey } `
                    -Method GET

                Write-Host "[REAL KEY USED]"
            }
            catch {
                Write-Host "[ERROR] Real key request failed"
            }
        }

        # FAKE key attack (20%)
        else {
            $fakeKey = Generate-AWSKey

            try {
                Invoke-RestMethod `
                    -Uri "$BASE_URL/cloud/instances" `
                    -Headers @{ "x-api-key" = $fakeKey } `
                    -Method GET

                Write-Host "[FAKE KEY USED]"
            }
            catch {
                Write-Host "[ERROR] Fake key request failed"
            }
        }

        Start-Sleep -Milliseconds $DELAY_MS
    }
}

Write-Host "Simulation complete."