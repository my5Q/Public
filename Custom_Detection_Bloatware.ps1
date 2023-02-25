$request = Invoke-WebRequest -URI https://raw.githubusercontent.com/my5Q/Public/main/Remove_Bloatware.ps1 -UseBasicParsing
$online_latest_version = $request.Content.Split([Environment]::NewLine) | Select-Object -First 1
$online_latest_version = $online_latest_version.split('"')[1]
<<<<<<< HEAD

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
=======
$penta_path = "C:\Program Files\5Q"
$info_json = (Get-Content "$penta_path\Remove_Bloatware_Info.json" -Raw) | ConvertFrom-Json
$local_version = $info_json.psobject.Properties.Where({ $_.Name -eq "script_version" }).Value
$TimeNow = Get-Date
$UTC = $TimeNow.ToUniversalTime().ToString("dd-MM-yyyy HH:mm:ss")
if ($local_version -eq $online_latest_version) {
    Write-Output "Local version $local_version is up to date at $UTC!"
    exit 0
}
else {
    Write-Output "Local version $local_version is NOT up to date at $UTC. Applying changes!"
    Invoke-WebRequest -URI https://raw.githubusercontent.com/my5Q/Public/main/Remove_Bloatware.ps1 -UseBasicParsing | Invoke-Expression -ErrorAction Continue
    exit 1
}
>>>>>>> 05e630a876463b1339f18e8f65560d804c1dbe34
