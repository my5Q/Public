$request = Invoke-WebRequest -URI https://raw.githubusercontent.com/edlial/PS-Scripts/zoja/Remove_bloatware.ps1 -UseBasicParsing
$online_latest_version = $request.Content.Split([Environment]::NewLine) | Select-Object -First 1
$online_latest_version = $online_latest_version.split('"')[1]

$penta_path = "C:\Program Files\5Q"
$info_json = (Get-Content "$penta_path\Remove_bloatware_info.json" -Raw) | ConvertFrom-Json
$local_version = $info_json.psobject.Properties.Where({ $_.Name -eq "script_version" }).Value

if ($local_version -eq $online_latest_version) {
    Write-Host "Script is already up to date !"
    exit 0
}
else {
    Write-Host "Applying Updates !"
    exit 1
}