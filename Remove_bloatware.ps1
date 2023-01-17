$latest_version = "2.01"
$penta_path = "C:\Program Files\5Q"
$info_json = (Get-Content "$penta_path\Remove_bloatware_info.json" -Raw) | ConvertFrom-Json
$local_version = $info_json.psobject.Properties.Where({ $_.Name -eq "script_version" }).Value

if ($local_version -eq $latest_version) {
    Write-Host "[ $(hostname) ] Script is already up to date !"
}
else {
    Write-Host "Applying Updates !"
    #update json file locally
    $jsonVar = @"
{
    "script_name": "Remove_bloatware",
    "script_version": "$latest_version",
    "computer_name": "$(hostname)"
}
"@
    
    If (!(test-path -PathType container $penta_path)) {
        New-Item -ItemType Directory -Path $penta_path
    }

    $jsonVar | Out-File "$penta_path\Remove_bloatware_info.json"

    Write-Host "======================================="
    Write-Host "---    Start Removing Bloatware     ---"
    Write-Host "           $(hostname)                 "
    Write-Host "======================================="

    #This function finds any AppX/AppXProvisioned package and uninstalls it, except for Freshpaint, Windows Calculator, Windows Store, and Windows Photos.
    #Also, to note - This does NOT remove essential system services/software/etc such as .NET framework installations, Cortana, Edge, etc.

    #This will self elevate the script so with a UAC prompt since this script needs to be run as an Administrator in order to function properly.
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
        Write-Host "You didn't run this script as an Administrator. This script will self elevate to run as an Administrator and continue."
        Start-Sleep 1
        Write-Host "                                               3"
        Start-Sleep 1
        Write-Host "                                               2"
        Start-Sleep 1
        Write-Host "                                               1"
        Start-Sleep 1
        Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
        Exit
    }

    #no errors throughout
    $ErrorActionPreference = 'silentlycontinue'

    Start-Transcript -OutputDirectory "$penta_path"

    Add-Type -AssemblyName PresentationCore, PresentationFramework

    Function DebloatAll {
        $Bloatware = @(
            #Unnecessary Windows 10 AppX Apps

            "2FE3CB00.PicsArt-PhotoStudio"
            "3DBuilder"
            "46928bounde.EclipseManager"
            "4DF9E0F8.Netflix"
            "613EBCEA.PolarrPhotoEditorAcademicEdition"
            "6Wunderkinder.Wunderlist"
            "7EE7776C.LinkedInforWindows"
            "89006A2E.AutodeskSketchBook"
            "9E2F88E3.Twitter"
            "A278AB0D.DisneyMagicKingdoms"
            "A278AB0D.MarchofEmpires"
            "ACGMediaPlayer"
            "ActiproSoftwareLLC"
            "ActiproSoftwareLLC.562882FEEB491"
            "AdobePhotoshopExpress"
            "AdobeSystemsIncorporated.AdobePhotoshopExpress"
            "Advertising"
            "AppConnector"
            "BingFinance"
            "BingFoodAndDrink"
            "BingHealthAndFitness"
            "BingNews"
            "BingSports"
            "BingTranslator"
            "BingTravel"
            "BingWeather"
            "BubbleWitch3Saga"
            "CAF9E577.Plex"
            "CandyCrush"
            "ClearChannelRadioDigital.iHeartRadio"
            "CommsPhone"
            "ConnectivityStore"
            "D52A8D61.FarmVille2CountryEscape"
            "D5EA27B7.Duolingo-LearnLanguagesforFree"
            "DB6EA5DB.CyberLinkMediaSuiteEssentials"
            "Dell"
            "Dolby"
            "DolbyLaboratories.DolbyAccess"
            "Drawboard.DrawboardPDF"
            "Duolingo-LearnLanguagesforFree"
            "EclipseManager"
            "Facebook"
            "Facebook.Facebook"
            "Fitbit.FitbitCoach"
            "flaregamesGmbH.RoyalRevolt2"
            "Flipboard"
            "Flipboard.Flipboard"
            "GAMELOFTSA.Asphalt8Airborne"
            "GamingServices"
            "GetHelp"
            "Getstarted"
            "HiddenCity"
            "HiddenCityMysteryofShadows"
            "HotspotShieldFreeVPN"
            "HPDesktopSupportUtilities"
            "HPEasyClean"
            "HPJumpStarts"
            "HPPCHardwareDiagnosticsWindows"
            "HPPowerManager"
            "HPPrivacySettings"
            "HPQuickDrop"
            "HPQuickTouch"
            "HPSupportAssistant"
            "HPSureShieldAI"
            "HPSystemInformation"
            "HPWorkWell"
            "Hulu"
            "KeeperSecurityInc.Keeper"
            "king.com."
            "king.com.BubbleWitch3Saga"
            "king.com.CandyCrushSaga"
            "king.com.CandyCrushSodaSaga"
            "Lens"
            "LinkedInforWindows"
            "Messaging"
            "Microsoft3DViewer"
            "MicrosoftOfficeHub"
            "MicrosoftSolitaireCollection"
            "MicrosoftStickyNotes"
            "Minecraft"
            "MinecraftUWP"
            "MixedReality.Portal"
            "MSPaint"
            "myHP"
            "Netflix"
            "NetworkSpeedTest"
            "News"
            "NORDCURRENT.COOKINGFEVER"
            "Office.Lens"
            "Office.OneNote"
            "Office.Sway"
            "Office.Todo.List"
            "OneCalendar"
            "OneConnect"
            "OneNote"
            "PandoraMediaInc"
            "PandoraMediaInc.29680B314EFC2"
            "People"
            "Playtika.CaesarsSlotsFreeCasino"
            "Print3D"
            "RemoteDesktop"
            "Royal Revolt"
            "ScreenSketch"
            "ShazamEntertainmentLtd.Shazam"
            "SkypeApp"
            "Speed Test"
            "Spotify"
            "SpotifyAB.SpotifyMusic"
            "StorePurchaseApp"
            "Sway"
            "TCUI"
            "TheNewYorkTimes.NYTCrossword"
            "ThumbmunkeysLtd.PhototasticCollage"
            "Todos"
            "TuneIn.TuneInRadio"
            "Twitter"
            "Viber"
            "Wallet"
            "Whiteboard"
            #"Windows.Photos"
            "WindowsAlarms"
            "WindowsCamera"
            "windowscommunicationsapps"
            "WindowsFeedbackHub"
            "WindowsMaps"
            "WindowsPhone"
            "WindowsSoundRecorder"
            "WinZipComputing.WinZipUniversal"
            "Wunderlist"
            "Xbox.TCUI"
            "XboxApp"
            "XboxGameCallableUI"
            "XboxGameOverlay"
            "XboxGamingOverlay"
            "XboxIdentityProvider"
            "XboxSpeechToTextOverlay"
            "XINGAG.XING"
            "YourPhone"
            "ZuneMusic"
            "ZuneVideo"
            #"WindowsCalculator"
            #"WindowsReadingList"
            #"WindowsStore"
        )

        $Other_Bloatware = @(
            #Dell
            "{4CCADC13-F3AE-454F-B724-33F6D4E52022}"
            "{4F8A3BC3-641C-4B0D-AF46-EA3354016EA7}"
            "{6DD27BB4-C350-414B-BC25-D33246605FB2}"
            "{E530ABB7-9DCC-421B-B751-484375E8374A}"
            "{10B1BCF9-4996-4270-A12D-1B1BFEEF979C}"
            "{E27862BD-4371-4245-896A-7EBE989B6F7F}"
            "{900D0BCD-0B86-4DAA-B639-89BE70449569}"
            "{08E7C8D5-F2B5-4F09-B0EA-F28913BEFDB0}"
            "{E0659C89-D276-4B77-A5EC-A8F2F042E78F}"
            "{286A9ADE-A581-43E8-AA85-6F5D58C7DC88}"
            "{a0d5bbde-c013-48ba-b98a-ca0ff5cf36a6}"
            "{e178914d-07c9-4d17-bd20-287c78ecc0f1}"
        )

        #get installed applications
        $installedApps = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, PSChildName, UninstallString | Where-Object { $_.DisplayName -ne $null }
        #get installed 64 bit applications
        $installedApps64 = Get-ItemProperty HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, PSChildName, UninstallString | Where-Object { $_.DisplayName -ne $null }
        #combine the two
        $installedApps = $installedApps + $installedApps64

        foreach ($Bloat in $Other_Bloatware) {
            $installedApps | Where-Object { $_.PSChildName -like "*$Bloat*" } | ForEach-Object {  
                Write-Host "Uninstalling $($_.PSChildName) ..." -ForegroundColor Green      
                if ($_.UninstallString -like "*MsiExec.exe*") {
                    Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $($_.PSChildName) /qn" -Wait 
                }
                else {
                    Start-Process -FilePath $_.UninstallString -ArgumentList "/S" -Wait 
                }
            }
        }

        # ## Teams Removal - Source: https://github.com/asheroto/UninstallTeams
        # function getUninstallString($match) {
        #     return (Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$match*" }).UninstallString
        # }
            
        # $TeamsPath = [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Microsoft', 'Teams')
        # $TeamsUpdateExePath = [System.IO.Path]::Combine($TeamsPath, 'Update.exe')
            
        # Write-Output "Stopping Teams process..."
        # Stop-Process -Name "*teams*" -Force -ErrorAction SilentlyContinue
        
        # Write-Output "Uninstalling Teams from AppData\Microsoft\Teams"
        # if ([System.IO.File]::Exists($TeamsUpdateExePath)) {
        #     # Uninstall app
        #     $proc = Start-Process $TeamsUpdateExePath "-uninstall -s" -PassThru
        #     $proc.WaitForExit()
        # }
        
        # Write-Output "Removing Teams AppxPackage..."
        # Get-AppxPackage "*Teams*" | Remove-AppxPackage -ErrorAction SilentlyContinue
        # Get-AppxPackage "*Teams*" -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        
        # Write-Output "Deleting Teams directory"
        # if ([System.IO.Directory]::Exists($TeamsPath)) {
        #     Remove-Item $TeamsPath -Force -Recurse -ErrorAction SilentlyContinue
        # }
        
        # Write-Output "Deleting Teams uninstall registry key"
        # # Uninstall from Uninstall registry key UninstallString
        # $us = getUninstallString("Teams");
        # if ($us.Length -gt 0) {
        #     $us = ($us.Replace("/I", "/uninstall ") + " /quiet").Replace("  ", " ")
        #     $FilePath = ($us.Substring(0, $us.IndexOf(".exe") + 4).Trim())
        #     $ProcessArgs = ($us.Substring($us.IndexOf(".exe") + 5).Trim().replace("  ", " "))
        #     $proc = Start-Process -FilePath $FilePath -Args $ProcessArgs -PassThru
        #     $proc.WaitForExit()
        # }
            
        # Write-Output "Restart computer to complete teams uninstall"
            
        Write-Host "Removing Bloatware"

        foreach ($Bloat in $Bloatware) {
            Get-AppxPackage -allusers  "*$Bloat*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*$Bloat*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
            Write-Host "Trying to remove $Bloat."
        }
            
        #Find and remove installed bloatwares with DISM
        $installed_bloatwares = DISM /Online /Get-ProvisionedAppxPackages | Where-Object { $_ -match "PackageName" }

        foreach ($Bloat in $installed_bloatwares) {
            $to_remove = $Bloat.substring(14) #Filter only the value of PackageName
            DISM /Online /Remove-ProvisionedAppxPackage /PackageName:$to_remove
            Write-Host "Removing $to_remove ."
        }

        # List of built-in apps to remove
        $UninstallPackages = @(
            "AD2F1837.HPJumpStarts"
            "AD2F1837.HPPCHardwareDiagnosticsWindows"
            "AD2F1837.HPPowerManager"
            "AD2F1837.HPPrivacySettings"
            "AD2F1837.HPSupportAssistant"
            "AD2F1837.HPSureShieldAI"
            "AD2F1837.HPSystemInformation"
            "AD2F1837.HPQuickDrop"
            "AD2F1837.HPWorkWell"
            "AD2F1837.myHP"
            "AD2F1837.HPDesktopSupportUtilities"
            "AD2F1837.HPQuickTouch"
            "AD2F1837.HPEasyClean"
            "AD2F1837.HPSystemInformation"
        )

        # List of programs to uninstall
        $UninstallPrograms = @(
            "HP Client Security Manager"
            "HP Connection Optimizer"
            "HP Documentation"
            "HP MAC Address Manager"
            "HP Notifications"
            "HP Security Update Service"
            "HP System Default Settings"
            "HP Sure Click"
            "HP Sure Click Security Browser"
            "HP Sure Run"
            "HP Sure Recover"
            "HP Sure Sense"
            "HP Sure Sense Installer"
            "HP Wolf Security"
            "HP Wolf Security Application Support for Sure Sense"
            "HP Wolf Security Application Support for Windows"
        )

        $HPidentifier = "AD2F1837"

        $InstalledPackages = Get-AppxPackage -AllUsers `
        | Where-Object { ($UninstallPackages -contains $_.Name) -or ($_.Name -match "^$HPidentifier") }

        $ProvisionedPackages = Get-AppxProvisionedPackage -Online `
        | Where-Object { ($UninstallPackages -contains $_.DisplayName) -or ($_.DisplayName -match "^$HPidentifier") }

        $InstalledPrograms = Get-Package | Where-Object { $UninstallPrograms -contains $_.Name }

        # Remove appx provisioned packages - AppxProvisionedPackage
        ForEach ($ProvPackage in $ProvisionedPackages) {

            Write-Host -Object "Attempting to remove provisioned package: [$($ProvPackage.DisplayName)]..."

            Try {
                $Null = Remove-AppxProvisionedPackage -PackageName $ProvPackage.PackageName -Online -ErrorAction Stop
                Write-Host -Object "Successfully removed provisioned package: [$($ProvPackage.DisplayName)]"
            }
            Catch { Write-Warning -Message "Failed to remove provisioned package: [$($ProvPackage.DisplayName)]" }
        }

        # Remove appx packages - AppxPackage
        ForEach ($AppxPackage in $InstalledPackages) {
                                            
            Write-Host -Object "Attempting to remove Appx package: [$($AppxPackage.Name)]..."

            Try {
                $Null = Remove-AppxPackage -Package $AppxPackage.PackageFullName -AllUsers -ErrorAction Stop
                Write-Host -Object "Successfully removed Appx package: [$($AppxPackage.Name)]"
            }
            Catch { Write-Warning -Message "Failed to remove Appx package: [$($AppxPackage.Name)]" }
        }

        # Remove installed programs
        $InstalledPrograms | ForEach-Object {

            Write-Host -Object "Attempting to uninstall: [$($_.Name)]..."

            Try {
                $Null = $_ | Uninstall-Package -AllVersions -Force -ErrorAction Stop
                Write-Host -Object "Successfully uninstalled: [$($_.Name)]"
            }
            Catch { Write-Warning -Message "Failed to uninstall: [$($_.Name)]" }
        }

        # Fallback attempt 1 to remove HP Wolf Security using msiexec
        Try {
            MsiExec /x "{0E2E04B0-9EDD-11EB-B38C-10604B96B11E}" /qn /norestart
            Write-Host -Object "Fallback to MSI uninistall for HP Wolf Security initiated"
        }
        Catch {
            Write-Warning -Object "Failed to uninstall HP Wolf Security using MSI - Error message: $($_.Exception.Message)"
        }

        # Fallback attempt 2 to remove HP Wolf Security using msiexec
        Try {
            MsiExec /x "{4DA839F0-72CF-11EC-B247-3863BB3CB5A8}" /qn /norestart
            Write-Host -Object "Fallback to MSI uninistall for HP Wolf 2 Security initiated"
        }
        Catch {
            Write-Warning -Object  "Failed to uninstall HP Wolf Security 2 using MSI - Error message: $($_.Exception.Message)"
        }

        Write-Host "Bloatwares Removed"
    }

    Function Remove-Keys {
        
        #These are the registry keys that it will delete.
            
        $Keys = @(
            
            #Remove Background Tasks
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
            #Windows File
            "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            
            #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
            #Scheduled Tasks to delete
            "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
            
            #Windows Protocol Keys
            "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
               
            #Windows Share Target
            "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        )
        
        #This writes the output of each key it is removing and also removes the keys listed above.
        ForEach ($Key in $Keys) {
            Write-Output "Removing $Key from registry"
            Remove-Item $Key -Recurse
        }
    }
            
    Function Protect-Privacy {
            
        #Disables Windows Feedback Experience
        Write-Output "Disabling Windows Feedback Experience program"
        $Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
        If (Test-Path $Advertising) {
            Set-ItemProperty $Advertising Enabled -Value 0 
        }
            
        #Stops Cortana from being used as part of your Windows Search Function
        Write-Output "Stopping Cortana from being used as part of your Windows Search Function"
        $Search = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        If (Test-Path $Search) {
            Set-ItemProperty $Search AllowCortana -Value 0 
        }

        #Disables Web Search in Start Menu
        Write-Output "Disabling Bing Search in Start Menu"
        $WebSearch = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" BingSearchEnabled -Value 0 
        If (!(Test-Path $WebSearch)) {
            New-Item $WebSearch
        }
        Set-ItemProperty $WebSearch DisableWebSearch -Value 1 
            
        #Stops the Windows Feedback Experience from sending anonymous data
        Write-Output "Stopping the Windows Feedback Experience program"
        $Period = "HKCU:\Software\Microsoft\Siuf\Rules"
        If (!(Test-Path $Period)) { 
            New-Item $Period
        }
        Set-ItemProperty $Period PeriodInNanoSeconds -Value 0 

        #Prevents bloatware applications from returning and removes Start Menu suggestions               
        Write-Output "Adding Registry key to prevent bloatware apps from returning"
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        $registryOEM = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
        If (!(Test-Path $registryPath)) { 
            New-Item $registryPath
        }
        Set-ItemProperty $registryPath DisableWindowsConsumerFeatures -Value 1 

        If (!(Test-Path $registryOEM)) {
            New-Item $registryOEM
        }
        Set-ItemProperty $registryOEM  ContentDeliveryAllowed -Value 0 
        Set-ItemProperty $registryOEM  OemPreInstalledAppsEnabled -Value 0 
        Set-ItemProperty $registryOEM  PreInstalledAppsEnabled -Value 0 
        Set-ItemProperty $registryOEM  PreInstalledAppsEverEnabled -Value 0 
        Set-ItemProperty $registryOEM  SilentInstalledAppsEnabled -Value 0 
        Set-ItemProperty $registryOEM  SystemPaneSuggestionsEnabled -Value 0          
    
        #Preping mixed Reality Portal for removal    
        Write-Output "Setting Mixed Reality Portal value to 0 so that you can uninstall it in Settings"
        $Holo = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic"    
        If (Test-Path $Holo) {
            Set-ItemProperty $Holo  FirstRunSucceeded -Value 0 
        }

        #Disables Wi-fi Sense
        Write-Output "Disabling Wi-Fi Sense"
        $WifiSense1 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
        $WifiSense2 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
        $WifiSense3 = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
        If (!(Test-Path $WifiSense1)) {
            New-Item $WifiSense1
        }
        Set-ItemProperty $WifiSense1  Value -Value 0 
        If (!(Test-Path $WifiSense2)) {
            New-Item $WifiSense2
        }
        Set-ItemProperty $WifiSense2  Value -Value 0 
        Set-ItemProperty $WifiSense3  AutoConnectAllowedOEM -Value 0 
        
        #Disables live tiles
        Write-Output "Disabling live tiles"
        $Live = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"    
        If (!(Test-Path $Live)) {      
            New-Item $Live
        }
        Set-ItemProperty $Live  NoTileApplicationNotification -Value 1 
        
        #Turns off Data Collection via the AllowTelemtry key by changing it to 0
        Write-Output "Turning off Data Collection"
        $DataCollection1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
        $DataCollection2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        $DataCollection3 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"    
        If (Test-Path $DataCollection1) {
            Set-ItemProperty $DataCollection1  AllowTelemetry -Value 0 
        }
        If (Test-Path $DataCollection2) {
            Set-ItemProperty $DataCollection2  AllowTelemetry -Value 0 
        }
        If (Test-Path $DataCollection3) {
            Set-ItemProperty $DataCollection3  AllowTelemetry -Value 0 
        }
    
        #Disabling Location Tracking
        Write-Output "Disabling Location Tracking"
        $SensorState = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
        $LocationConfig = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
        If (!(Test-Path $SensorState)) {
            New-Item $SensorState
        }
        Set-ItemProperty $SensorState SensorPermissionState -Value 0 
        If (!(Test-Path $LocationConfig)) {
            New-Item $LocationConfig
        }
        Set-ItemProperty $LocationConfig Status -Value 0 
        
        #Disables People icon on Taskbar
        Write-Output "Disabling People icon on Taskbar"
        $People = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
        If (Test-Path $People) {
            Set-ItemProperty $People -Name PeopleBand -Value 0
        }
        
        #Disables scheduled tasks that are considered unnecessary 
        Write-Output "Disabling scheduled tasks"
        Get-ScheduledTask  XblGameSaveTaskLogon | Disable-ScheduledTask
        Get-ScheduledTask  XblGameSaveTask | Disable-ScheduledTask
        Get-ScheduledTask  Consolidator | Disable-ScheduledTask
        Get-ScheduledTask  UsbCeip | Disable-ScheduledTask
        Get-ScheduledTask  DmClient | Disable-ScheduledTask
        Get-ScheduledTask  DmClientOnScenarioDownload | Disable-ScheduledTask

        Write-Output "Stopping and disabling Diagnostics Tracking Service"
        #Disabling the Diagnostics Tracking Service
        Stop-Service "DiagTrack"
        Set-Service "DiagTrack" -StartupType Disabled

    
        Write-Output "Removing CloudStore from registry if it exists"
        $CloudStore = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore'
        If (Test-Path $CloudStore) {
            Stop-Process Explorer.exe -Force -ErrorAction SilentlyContinue
            Remove-Item $CloudStore -Recurse -Force
            Start-Process Explorer.exe -Wait
        }
    }

    Function DisableCortana {
        Write-Host "Disabling Cortana"
        $Cortana1 = "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
        $Cortana2 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
        $Cortana3 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
        If (!(Test-Path $Cortana1)) {
            New-Item $Cortana1
        }
        Set-ItemProperty $Cortana1 AcceptedPrivacyPolicy -Value 0 
        If (!(Test-Path $Cortana2)) {
            New-Item $Cortana2
        }
        Set-ItemProperty $Cortana2 RestrictImplicitTextCollection -Value 1 
        Set-ItemProperty $Cortana2 RestrictImplicitInkCollection -Value 1 
        If (!(Test-Path $Cortana3)) {
            New-Item $Cortana3
        }
        Set-ItemProperty $Cortana3 HarvestContacts -Value 0
    
    }

    Function EnableCortana {
        Write-Host "Re-enabling Cortana"
        $Cortana1 = "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
        $Cortana2 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
        $Cortana3 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
        If (!(Test-Path $Cortana1)) {
            New-Item $Cortana1
        }
        Set-ItemProperty $Cortana1 AcceptedPrivacyPolicy -Value 1 
        If (!(Test-Path $Cortana2)) {
            New-Item $Cortana2
        }
        Set-ItemProperty $Cortana2 RestrictImplicitTextCollection -Value 0 
        Set-ItemProperty $Cortana2 RestrictImplicitInkCollection -Value 0 
        If (!(Test-Path $Cortana3)) {
            New-Item $Cortana3
        }
        Set-ItemProperty $Cortana3 HarvestContacts -Value 1 
    }
        
    Function Stop-EdgePDF {
    
        #Stops edge from taking over as the default .PDF viewer    
        Write-Output "Stopping Edge from taking over as the default .PDF viewer"
        $NoPDF = "HKCR:\.pdf"
        $NoProgids = "HKCR:\.pdf\OpenWithProgids"
        $NoWithList = "HKCR:\.pdf\OpenWithList" 
        If (!(Get-ItemProperty $NoPDF  NoOpenWith)) {
            New-ItemProperty $NoPDF NoOpenWith 
        }        
        If (!(Get-ItemProperty $NoPDF  NoStaticDefaultVerb)) {
            New-ItemProperty $NoPDF  NoStaticDefaultVerb 
        }        
        If (!(Get-ItemProperty $NoProgids  NoOpenWith)) {
            New-ItemProperty $NoProgids  NoOpenWith 
        }        
        If (!(Get-ItemProperty $NoProgids  NoStaticDefaultVerb)) {
            New-ItemProperty $NoProgids  NoStaticDefaultVerb 
        }        
        If (!(Get-ItemProperty $NoWithList  NoOpenWith)) {
            New-ItemProperty $NoWithList  NoOpenWith
        }        
        If (!(Get-ItemProperty $NoWithList  NoStaticDefaultVerb)) {
            New-ItemProperty $NoWithList  NoStaticDefaultVerb 
        }
            
        #Appends an underscore '_' to the Registry key for Edge
        $Edge = "HKCR:\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_"
        If (Test-Path $Edge) {
            Set-Item $Edge AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_ 
        }
    }

    Function Undo-Changes {   
        
        #This function will revert the changes you made when running the Start-Debloat function.
        
        #This line reinstalls all of the bloatware that was removed
        Get-AppxPackage -AllUsers | ForEach-Object { Add-AppxPackage -Verbose -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" } 
    
        #Tells Windows to enable your advertising information.    
        Write-Output "Re-enabling key to show advertisement information"
        $Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
        If (Test-Path $Advertising) {
            Set-ItemProperty $Advertising  Enabled -Value 1
        }
            
        #Enables Cortana to be used as part of your Windows Search Function
        Write-Output "Re-enabling Cortana to be used in your Windows Search"
        $Search = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        If (Test-Path $Search) {
            Set-ItemProperty $Search  AllowCortana -Value 1 
        }
            
        #Re-enables the Windows Feedback Experience for sending anonymous data
        Write-Output "Re-enabling Windows Feedback Experience"
        $Period = "HKCU:\Software\Microsoft\Siuf\Rules"
        If (!(Test-Path $Period)) { 
            New-Item $Period
        }
        Set-ItemProperty $Period PeriodInNanoSeconds -Value 1 
    
        #Enables bloatware applications               
        Write-Output "Adding Registry key to allow bloatware apps to return"
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        If (!(Test-Path $registryPath)) {
            New-Item $registryPath 
        }
        Set-ItemProperty $registryPath  DisableWindowsConsumerFeatures -Value 0 
        
        #Changes Mixed Reality Portal Key 'FirstRunSucceeded' to 1
        Write-Output "Setting Mixed Reality Portal value to 1"
        $Holo = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic"
        If (Test-Path $Holo) {
            Set-ItemProperty $Holo  FirstRunSucceeded -Value 1 
        }
        
        #Re-enables live tiles
        Write-Output "Enabling live tiles"
        $Live = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
        If (!(Test-Path $Live)) {
            New-Item $Live 
        }
        Set-ItemProperty $Live  NoTileApplicationNotification -Value 0 
       
        #Re-enables data collection
        Write-Output "Re-enabling data collection"
        $DataCollection = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
        If (!(Test-Path $DataCollection)) {
            New-Item $DataCollection
        }
        Set-ItemProperty $DataCollection  AllowTelemetry -Value 1
        
        #Re-enables People Icon on Taskbar
        Write-Output "Enabling People icon on Taskbar"
        $People = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"
        If (!(Test-Path $People)) {
            New-Item $People 
        }
        Set-ItemProperty $People  PeopleBand -Value 1 
    
        #Re-enables suggestions on start menu
        Write-Output "Enabling suggestions on the Start Menu"
        $Suggestions = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
        If (!(Test-Path $Suggestions)) {
            New-Item $Suggestions
        }
        Set-ItemProperty $Suggestions  SystemPaneSuggestionsEnabled -Value 1 
        
        #Re-enables scheduled tasks that were disabled when running the Debloat switch
        Write-Output "Enabling scheduled tasks that were disabled"
        Get-ScheduledTask XblGameSaveTaskLogon | Enable-ScheduledTask 
        Get-ScheduledTask  XblGameSaveTask | Enable-ScheduledTask 
        Get-ScheduledTask  Consolidator | Enable-ScheduledTask 
        Get-ScheduledTask  UsbCeip | Enable-ScheduledTask 
        Get-ScheduledTask  DmClient | Enable-ScheduledTask 
        Get-ScheduledTask  DmClientOnScenarioDownload | Enable-ScheduledTask 

        Write-Output "Re-enabling and starting WAP Push Service"
        #Enable and start WAP Push Service
        Set-Service "dmwappushservice" -StartupType Automatic
        Start-Service "dmwappushservice"
    
        Write-Output "Re-enabling and starting the Diagnostics Tracking Service"
        #Enabling the Diagnostics Tracking Service
        Set-Service "DiagTrack" -StartupType Automatic
        Start-Service "DiagTrack"
    
        Write-Output "Restoring 3D Objects in the 'My Computer' submenu in explorer"
        #Restoring 3D Objects in the 'My Computer' submenu in explorer
        Restore3dObjects
    }

    Function CheckDMWService {

        Param([switch]$Debloat)
  
        If (Get-Service -Name dmwappushservice | Where-Object { $_.StartType -eq "Disabled" }) {
            Set-Service -Name dmwappushservice -StartupType Automatic
        }

        If (Get-Service -Name dmwappushservice | Where-Object { $_.Status -eq "Stopped" }) {
            Start-Service -Name dmwappushservice
        } 
    }
    
    Function Enable-EdgePDF {
        Write-Output "Setting Edge back to default"
        $NoPDF = "HKCR:\.pdf"
        $NoProgids = "HKCR:\.pdf\OpenWithProgids"
        $NoWithList = "HKCR:\.pdf\OpenWithList"
        #Sets edge back to default
        If (Get-ItemProperty $NoPDF  NoOpenWith) {
            Remove-ItemProperty $NoPDF  NoOpenWith
        } 
        If (Get-ItemProperty $NoPDF  NoStaticDefaultVerb) {
            Remove-ItemProperty $NoPDF  NoStaticDefaultVerb 
        }       
        If (Get-ItemProperty $NoProgids  NoOpenWith) {
            Remove-ItemProperty $NoProgids  NoOpenWith 
        }        
        If (Get-ItemProperty $NoProgids  NoStaticDefaultVerb) {
            Remove-ItemProperty $NoProgids  NoStaticDefaultVerb 
        }        
        If (Get-ItemProperty $NoWithList  NoOpenWith) {
            Remove-ItemProperty $NoWithList  NoOpenWith
        }    
        If (Get-ItemProperty $NoWithList  NoStaticDefaultVerb) {
            Remove-ItemProperty $NoWithList  NoStaticDefaultVerb
        }
        
        #Removes an underscore '_' from the Registry key for Edge
        $Edge2 = "HKCR:\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_"
        If (Test-Path $Edge2) {
            Set-Item $Edge2 AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723
        }
    }

    Function FixWhitelistedApps {
        
        If (!(Get-AppxPackage -AllUsers | Select-Object Microsoft.Paint3D, Microsoft.WindowsCalculator, Microsoft.WindowsStore, Microsoft.Windows.Photos)) {
    
            #Credit to abulgatz for these 4 lines of code
            Get-AppxPackage -allusers Microsoft.Paint3D | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
            Get-AppxPackage -allusers Microsoft.WindowsCalculator | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
            Get-AppxPackage -allusers Microsoft.WindowsStore | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
            Get-AppxPackage -allusers Microsoft.Windows.Photos | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" } 
        } 
    }

    Function UninstallOneDrive {

        Write-Host "Checking for pre-existing files and folders located in the OneDrive folders..."
        Start-Sleep 1
        If (Test-Path "$env:USERPROFILE\OneDrive\*") {
            Write-Host "Files found within the OneDrive folder! Checking to see if a folder named OneDriveBackupFiles exists."
            Start-Sleep 1
              
            If (Test-Path "$env:USERPROFILE\Desktop\OneDriveBackupFiles") {
                Write-Host "A folder named OneDriveBackupFiles already exists on your desktop. All files from your OneDrive location will be moved to that folder." 
            }
            else {
                If (!(Test-Path "$env:USERPROFILE\Desktop\OneDriveBackupFiles")) {
                    Write-Host "A folder named OneDriveBackupFiles will be created and will be located on your desktop. All files from your OneDrive location will be located in that folder."
                    New-item -Path "$env:USERPROFILE\Desktop" -Name "OneDriveBackupFiles"-ItemType Directory -Force
                    Write-Host "Successfully created the folder 'OneDriveBackupFiles' on your desktop."
                }
            }
            Start-Sleep 1
            Move-Item -Path "$env:USERPROFILE\OneDrive\*" -Destination "$env:USERPROFILE\Desktop\OneDriveBackupFiles" -Force
            Write-Host "Successfully moved all files/folders from your OneDrive folder to the folder 'OneDriveBackupFiles' on your desktop."
            Start-Sleep 1
            Write-Host "Proceeding with the removal of OneDrive."
            Start-Sleep 1
        }
        Else {
            Write-Host "Either the OneDrive folder does not exist or there are no files to be found in the folder. Proceeding with removal of OneDrive."
            Start-Sleep 1
            Write-Host "Enabling the Group Policy 'Prevent the usage of OneDrive for File Storage'."
            $OneDriveKey = 'HKLM:Software\Policies\Microsoft\Windows\OneDrive'
            If (!(Test-Path $OneDriveKey)) {
                Mkdir $OneDriveKey
                Set-ItemProperty $OneDriveKey -Name OneDrive -Value DisableFileSyncNGSC
            }
            Set-ItemProperty $OneDriveKey -Name OneDrive -Value DisableFileSyncNGSC
        }

        Write-Host "Uninstalling OneDrive. Please wait..."
    

        New-PSDrive  HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
        $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
        $ExplorerReg1 = "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
        $ExplorerReg2 = "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
        Stop-Process -Name "OneDrive*" -Force 
        Start-Sleep 2
        If (!(Test-Path $onedrive)) {
            $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"

            New-PSDrive  HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
            $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
            $ExplorerReg1 = "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
            $ExplorerReg2 = "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
            Stop-Process -Name "OneDrive*" -Force
            Start-Sleep 2
            If (!(Test-Path $onedrive)) {
                $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
            }
            Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
            Start-Sleep 2
            Write-Output "Stopping explorer"
            Start-Sleep 1
            taskkill.exe /F /IM explorer.exe
            Start-Sleep 3
            Write-Output "Removing leftover files"
            Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse
            Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse
            Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse
            If (Test-Path "$env:SYSTEMDRIVE\OneDriveTemp") {
                Remove-Item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse
            }
            Write-Output "Removing OneDrive from windows explorer"
            If (!(Test-Path $ExplorerReg1)) {
                New-Item $ExplorerReg1
            }
            Set-ItemProperty $ExplorerReg1 System.IsPinnedToNameSpaceTree -Value 0 
            If (!(Test-Path $ExplorerReg2)) {
                New-Item $ExplorerReg2
            }
            Set-ItemProperty $ExplorerReg2 System.IsPinnedToNameSpaceTree -Value 0
            Write-Output "Restarting Explorer that was shut down before."
            Start-Process explorer.exe -NoNewWindow
    
            Write-Host "Enabling the Group Policy 'Prevent the usage of OneDrive for File Storage'."
            $OneDriveKey = 'HKLM:Software\Policies\Microsoft\Windows\OneDrive'
            If (!(Test-Path $OneDriveKey)) {
                Mkdir $OneDriveKey 
            }
            Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
            Start-Sleep 2
            Write-Host "Stopping explorer"
            Start-Sleep 1
            taskkill.exe /F /IM explorer.exe
            Start-Sleep 3
            Write-Host "Removing leftover files"
            If (Test-Path "$env:USERPROFILE\OneDrive") {
                Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse
            }
            If (Test-Path "$env:LOCALAPPDATA\Microsoft\OneDrive") {
                Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse
            }
            If (Test-Path "$env:PROGRAMDATA\Microsoft OneDrive") {
                Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse
            }
            If (Test-Path "$env:SYSTEMDRIVE\OneDriveTemp") {
                Remove-Item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse
            }
            Write-Host "Removing OneDrive from windows explorer"
            If (!(Test-Path $ExplorerReg1)) {
                New-Item $ExplorerReg1
            }
            Set-ItemProperty $ExplorerReg1 System.IsPinnedToNameSpaceTree -Value 0 
            If (!(Test-Path $ExplorerReg2)) {
                New-Item $ExplorerReg2
            }
            Set-ItemProperty $ExplorerReg2 System.IsPinnedToNameSpaceTree -Value 0
            Write-Host "Restarting Explorer that was shut down before."
            Start-Process explorer.exe -NoNewWindow
            Write-Host "OneDrive has been successfully uninstalled!"
        
            Remove-item env:OneDrive
        }
    }

    Function UnpinStart {
        # https://superuser.com/a/1442733
        #Requires -RunAsAdministrator

        $START_MENU_LAYOUT = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
    <LayoutOptions StartTileGroupCellWidth="6" />
    <DefaultLayoutOverride>
        <StartLayoutCollection>
            <defaultlayout:StartLayout GroupCellWidth="6" />
        </StartLayoutCollection>
    </DefaultLayoutOverride>
</LayoutModificationTemplate>
"@

        $layoutFile = "C:\Windows\StartMenuLayout.xml"

        #Delete layout file if it already exists
        If (Test-Path $layoutFile) {
            Remove-Item $layoutFile
        }

        #Creates the blank layout file
        $START_MENU_LAYOUT | Out-File $layoutFile -Encoding ASCII

        $regAliases = @("HKLM", "HKCU")

        #Assign the start layout and force it to apply with "LockedStartLayout" at both the machine and user level
        foreach ($regAlias in $regAliases) {
            $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
            $keyPath = $basePath + "\Explorer" 
            IF (!(Test-Path -Path $keyPath)) { 
                New-Item -Path $basePath -Name "Explorer"
            }
            Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1
            Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile
        }

        #Restart Explorer, open the start menu (necessary to load the new layout), and give it a few seconds to process
        Stop-Process -name explorer -Force
        Start-Sleep -s 5
        $wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys('^{ESCAPE}')
        Start-Sleep -s 5

        #Enable the ability to pin items again by disabling "LockedStartLayout"
        foreach ($regAlias in $regAliases) {
            $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
            $keyPath = $basePath + "\Explorer" 
            Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0
        }

        #Restart Explorer and delete the layout file
        Stop-Process -name explorer -Force

        # Uncomment the next line to make clean start menu default for all new users
        #Import-StartLayout -LayoutPath $layoutFile -MountPath $env:SystemDrive\

        Remove-Item $layoutFile
    }

    Function Remove3dObjects {
        #Removes 3D Objects from the 'My Computer' submenu in explorer
        Write-Host "Removing 3D Objects from explorer 'My Computer' submenu"
        $Objects32 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
        $Objects64 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
        If (Test-Path $Objects32) {
            Remove-Item $Objects32 -Recurse 
        }
        If (Test-Path $Objects64) {
            Remove-Item $Objects64 -Recurse 
        }
    }

    Function Restore3dObjects {
        #Restores 3D Objects from the 'My Computer' submenu in explorer
        Write-Host "Restoring 3D Objects from explorer 'My Computer' submenu"
        $Objects32 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
        $Objects64 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
        If (!(Test-Path $Objects32)) {
            New-Item $Objects32
        }
        If (!(Test-Path $Objects64)) {
            New-Item $Objects64
        }
    }

    Function DisableLastUsedFilesAndFolders {
        Write-Host = "Disable Explorer to show last used files and folders."
        Invoke-Item (Start-Process powershell ((Split-Path $MyInvocation.InvocationName) + "\Individual Scripts\Disable Last Used Files and Folders View.ps1"))
    }

    #Creates a "drive" to access the HKCR (HKEY_CLASSES_ROOT)
    Write-Host "Creating PSDrive 'HKCR' (HKEY_CLASSES_ROOT). This will be used for the duration of the script as it is necessary for the removal and modification of specific registry keys."
    New-PSDrive  HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
    Start-Sleep 1
    Write-Host "Uninstalling bloatware, please wait."
    DebloatAll
    Write-Host "Bloatware removed."
    Start-Sleep 1
    Write-Host "Removing specific registry keys."
    Remove-Keys
    Write-Host "Leftover bloatware registry keys removed."
    Start-Sleep 1
    Write-Host "Checking to see if any Whitelisted Apps were removed, and if so re-adding them."
    Start-Sleep 1
    FixWhitelistedApps
    Start-Sleep 1
    Write-Host "Disabling Cortana from search, disabling feedback to Microsoft, and disabling scheduled tasks that are considered to be telemetry or unnecessary."
    Protect-Privacy
    Start-Sleep 1
    DisableCortana
    Write-Host "Cortana disabled and removed from search, feedback to Microsoft has been disabled, and scheduled tasks are disabled."
    Start-Sleep 1
    Write-Host "Stopping and disabling Diagnostics Tracking Service"
    DisableDiagTrack
    Write-Host "Diagnostics Tracking Service disabled"
    Start-Sleep 1
    Write-Host "Disabling WAP push service"
    DisableWAPPush
    Start-Sleep 1
    Write-Host "Re-enabling DMWAppushservice if it was disabled"
    CheckDMWService
    Start-Sleep 1
    Write-Host "Removing 3D Objects from the 'My Computer' submenu in explorer"
    Remove3dObjects
    Start-Sleep 1
    Stop-EdgePDF
    #UninstallOneDrive
    #Write-Host "OneDrive is now removed from the computer."
    UnpinStart
    Write-Host "Start Apps unpined."

    Write-Host "======================================="
    Write-Host "---   Finished Removing Bloatware   ---"
    Write-Host "           $(hostname)                 "
    Write-Host "======================================="

} 