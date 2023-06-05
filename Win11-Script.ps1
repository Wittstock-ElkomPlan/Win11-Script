 Default preset
$tweaks = @(
	#"AskQuestions",
	"CreateRestorePoint",
	### Require administrator privileges ###
	"RequireAdmin",
	"EnableNumpad",
    ### Security Tweaks ###
	"SetUACLow",                  # "SetUACHigh",
    "DisableSMB1",                # "EnableSMB1",	
	"SetCurrentNetworkPrivate",     # "SetCurrentNetworkPublic",	
	"EnableF8BootMenu",             # "DisableF8BootMenu",
    
    
    ### Explorer UI Tweaks ###
	"ShowKnownExtensions",          # "HideKnownExtensions",
    "ShowThisPCOnDesktop", #"HideThisPCFromDesktop",
	"ShowUserFolderOnDesktop",    # "HideUserFolderFromDesktop",
    
    "UninstallXPSPrinter",          # "InstallXPSPrinter",
	"RemoveFaxPrinter",             # "AddFaxPrinter",
    
    ### External Program Setup
	"InstallTitusProgs", #REQUIRED FOR OTHER PROGRAM INSTALLS!
    
    "InstallAdobe",
	#"InstallOpenShell",
	"InstallFirefox",
	"InstallVLC",
	"InstallWinrar",
	"InstallTotalcommander",
	"InstallRemoteTools",
		
	## Elkom
	"DisableTaskbarGrouping",
	"ShowAllIconsInNotificationArea",
	"HideTaskViewButton",
	"HideCortanaButton",
	"DisableAutostartOneDrive",
	"DisableAutostartSkype",
	"DisableFastboot",
	"EnergyHighPerformance",
	"DisableUDPonRemoteDesktop",	
	"Netzwerkverbindungen",
	"EnableNetFx3",
	"ChangeDriveLabelC",
	"DisableOffice365SimplifiedAccountCreation"
    
    )
##########
# Auxiliary Functions
##########

# Relaunch the script with administrator privileges
Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
		Exit
	}
}

# Wait for key press
Function WaitForKey {
	Write-Output "Setup complete, Check log for errors, Press any key to reboot..."
	[Console]::ReadKey($true) | Out-Null
}

# Restart computer
Function Restart {
	Write-Output "Restarting..."
	Restart-Computer
}

    
#########
# Recommended Titus Programs
#########

Function InstallTitusProgs {
	Write-Output "Installing Chocolatey"
	Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
	choco install chocolatey-core.extension -y
	Write-Output "Running O&O Shutup with Recommended Settings"
	Import-Module BitsTransfer
	$path = "C:\_Programme"
	If(!(test-path $path))
		{
      		New-Item -ItemType Directory -Force -Path $path
		}	
	Start-BitsTransfer -Source "https://raw.githubusercontent.com/ChrisTitusTech/win10script/master/ooshutup10.cfg" -Destination C:\_Programme\ooshutup10.cfg
	Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination C:\_Programme\OOSU10.exe
	Start-Process -FilePath "C:\_Programme\OOSU10.exe" -ArgumentList "C:\_Programme\ooshutup10.cfg /quiet"

}

Function InstallAdobe {
	Write-Output "Installing Adobe Acrobat Reader"
	choco install adobereader -y -params "/DesktopIcon"
}

Function InstallOpenShell {
	Write-Output "Installing open-shell"
	choco install open-shell -y
}

Function InstallFirefox {
	Write-Output "Installing firefox"
	choco install firefox -y --params "/l:de /RemoveDistributionDir" 
}

Function InstallVLC {
	Write-Output "Installing VLC"
	choco install vlc -y --params "/Language:de"
}

Function InstallWinrar {
	Write-Output "Installing winrar"
	choco install winrar -y	
	Set-ItemProperty -Path "HKCU:\Software\WinRAR\Setup" -Name "CascadedMenu" -Type DWord -Value 1 
}

Function InstallTotalcommander {
	Write-Output "Installing totalcommander"
	choco install totalcommander -y --params '/DesktopIcon /InstallPath=%programfiles(x86)%\totalcmd'
	$path = "%APPDATA%\GHISLER"
	If(!(test-path $path))
	{
      	New-Item -ItemType Directory -Force -Path $path
	}
	Start-BitsTransfer -Source "https://raw.githubusercontent.com/Wittstock-ElkomPlan/win10script/master/wincmd.ini" -Destination "$env:APPDATA\GHISLER\wincmd.ini"
	if (Test-Path "$HOME\Desktop\Total Commander 64 bit.lnk") {
		rm "$HOME\Desktop\Total Commander 64 bit.lnk"
	}
	if (Test-Path "C:\Users\Public\Desktop\Total Commander 64 bit.lnk") {
		rm "C:\Users\Public\Desktop\Total Commander 64 bit.lnk"
	}
	
}

Function InstallRemoteTools {
	Write-Output "Installing RemoteTools"	
	$path = "C:\_Programme"
	If(!(test-path $path))
		{
      		New-Item -ItemType Directory -Force -Path $path
		}
	curl -Uri "https://www.elkom-plan.de/storage/downloads/ELKOM-PLAN Teamviewer.exe" -OutFile "C:\_Programme\Teamviewer ELKOM-PLAN.exe"
	cp "C:\_Programme\Teamviewer ELKOM-PLAN.exe" "C:\Users\Public\Desktop\"


	curl -Uri "https://www.elkom-plan.de/storage/downloads/EP-Client6.exe" -OutFile "C:\_Programme\ELKOM-PLAN Fernwartung.exe"
	cp "C:\_Programme\ELKOM-PLAN Fernwartung.exe" "C:\Users\Public\Desktop\"
}

##########
# Security Tweaks
##########

# Lower UAC level (disabling it completely would break apps)
Function SetUACLow {
	Write-Output "Lowering UAC level..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
}

# Raise UAC level
Function SetUACHigh {
	Write-Output "Raising UAC level..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
}

# Disable obsolete SMB 1.0 protocol - Disabled by default since 1709
Function DisableSMB1 {
	Write-Output "Disabling SMB 1.0 protocol..."
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

# Enable obsolete SMB 1.0 protocol - Disabled by default since 1709
Function EnableSMB1 {
	Write-Output "Enabling SMB 1.0 protocol..."
	Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
}

# Set current network profile to private (allow file sharing, device discovery, etc.)
Function SetCurrentNetworkPrivate {
	Write-Output "Setting current network profile to private..."
	Set-NetConnectionProfile -NetworkCategory Private
}

# Set current network profile to public (deny file sharing, device discovery, etc.)
Function SetCurrentNetworkPublic {
	Write-Output "Setting current network profile to public..."
	Set-NetConnectionProfile -NetworkCategory Public
}

##########
#
##########

# Show This PC shortcut on desktop
Function ShowThisPCOnDesktop {
	Write-Output "Showing This PC shortcut on desktop..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
}

# Hide This PC shortcut from desktop
Function HideThisPCFromDesktop {
	Write-Output "Hiding This PC shortcut from desktop..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue
}

# Show User Folder shortcut on desktop
Function ShowUserFolderOnDesktop {
	Write-Output "Showing User Folder shortcut on desktop..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0
}

# Hide User Folder shortcut from desktop
Function HideUserFolderFromDesktop {
	Write-Output "Hiding User Folder shortcut from desktop..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ErrorAction SilentlyContinue
}


# Show known file extensions
Function ShowKnownExtensions {
	Write-Output "Showing known file extensions..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
}

# Hide known file extensions
Function HideKnownExtensions {
	Write-Output "Hiding known file extensions..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 1
}

Function DisableTaskbarGrouping {
	Write-Output "DisableTaskbarGrouping..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 2 	
}

Function HideTaskViewButton {
	Write-Output "HideTaskViewButton..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0 	
}

Function HideCortanaButton {
	Write-Output "HideCortanaButton..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0 	
}

Function ShowAllIconsInNotificationArea {
	Write-Output "ShowAllIconsInNotificationArea..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0 	
}

Function HideSearchBoxinTaskbar {
	Write-Output "HideHideSearchBoxinTaskbar..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0 	
}


Function DisableAutostartOneDrive {
	Write-Output "DisableAutostartOneDrive..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDrive" -ErrorAction SilentlyContinue	
}

Function DisableAutostartSkype {
	Write-Output "DisableAutostartSkype..."
	New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR
	$keypath = "HKCR:\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.SkypeApp_kzf8qxf38zg5c\SkypeStartup"
	if (-not (Test-Path $keypath)){
		New-Item -Path $keypath -ItemType Key -Force
	}
	Set-ItemProperty -Path "HKCR:\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.SkypeApp_kzf8qxf38zg5c\SkypeStartup" -Name "State" -Type DWord -Value 1 -Force
}

Function DisableFastboot {
	Write-Output "DisableDisableFastboot..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0 	
}

Function EnergyHighPerformance {
	$schemes = powercfg /L
	if ($schemes -match "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c") 
		{
		Write-Output "power scheme High Performance exists"
		} else {		
		Write-Output "add power scheme High Performance"
		powercfg -duplicatescheme "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
		}		
	"Power Button is Shutdown"
	powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 3
	powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 3
	Write-Host "Setting power scheme to High Performance" 
        PowerCfg -s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c	
}

Function DisableUDPonRemoteDesktop {
	Write-Output "DisableUDPonRemoteDesktop..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" -Name "fClientDisableUDP" -Type DWord -Value 1 	
}

Function EnableNumpad {
	Write-Output "EnableNumpad..."
	do
 {
    Clear-Host
    Write-Host "================ Do You Want to Enable Numpad on Windows Start? ================"
    Write-Host "Y: Press 'Y' to do this."
    Write-Host "N: Press 'N' to skip this."
    #Write-Host "Q: Press 'Q' to stop the entire script."
    $selection = Read-Host "Please make a selection"
    switch ($selection)
    {
    'y' { 		 	
		Set-ItemProperty -Path "REGISTRY::HKEY_USERS\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type String -Value 2147483650
	}
    'n' { Break }
    #'q' { Exit  }
    }
 }
 until ($selection -match "y" -or $selection -match "n" -or $selection -match "q")
		
}

Function Netzwerkverbindungen {
	Write-Output "Netzwerkverbindungen als Admin..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Type DWord -Value 1 	
}

Function EnableNetFx3 {
	Write-Output "Enable .net Framework 3.5"
	Dism /online /Enable-Feature /FeatureName:"NetFx3"	
}

Function ChangeDriveLabelC {
	Write-Output "Change Drive Label OS"
	Set-Volume -DriveLetter C -NewFileSystemLabel "OS"	
}

# Enable F8 boot menu options
Function EnableF8BootMenu {
	Write-Output "Enabling F8 boot menu options..."
	bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null
}

# Disable F8 boot menu options
Function DisableF8BootMenu {
	Write-Output "Disabling F8 boot menu options..."
	bcdedit /set `{current`} bootmenupolicy Standard | Out-Null
}

# Uninstall Microsoft XPS Document Writer
Function UninstallXPSPrinter {
	Write-Output "Uninstalling Microsoft XPS Document Writer..."
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Microsoft XPS Document Writer
Function InstallXPSPrinter {
	Write-Output "Installing Microsoft XPS Document Writer..."
	Enable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Remove Default Fax Printer
Function RemoveFaxPrinter {
	Write-Output "Removing Default Fax Printer..."
	Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue
}

# Add Default Fax Printer
Function AddFaxPrinter {
	Write-Output "Adding Default Fax Printer..."
	Add-Printer -Name "Fax" -DriverName "Microsoft Shared Fax Driver" -PortName "SHRFAX:" -ErrorAction SilentlyContinue
}


Function DisableOffice365SimplifiedAccountCreation {
	Write-Output "Disable Office 365 Simplified Account Creation..."
	$keypath = "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\setup"
	if (-not (Test-Path $keypath)){
		New-Item -Path $keypath -ItemType Key -Force
	}
	Set-ItemProperty -Path $keypath -Name "DisableOffice365SimplifiedAccountCreation" -Type DWord -Value 1 -Force

	$keypath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Outlook\setup"
	if (-not (Test-Path $keypath)){ 
 		New-Item -Path $keypath -ItemType Key -Force
	}
	Set-ItemProperty -Path $keypath -Name "DisableOffice365SimplifiedAccountCreation" -Type DWord -Value 1 -Force
	
	$keypath = "HKCU:\Software\Microsoft\Office\16.0\Outlook\AutoDiscover"
	if (-not (Test-Path $keypath)){ 
 		New-Item -Path $keypath -ItemType Key -Force
	}
	Set-ItemProperty -Path $keypath -Name "ExcludeExplicitO365Endpoint" -Type DWord -Value 0 -Force
}

Function CreateRestorePoint {
  	Write-Output "Creating Restore Point incase something bad happens"
  	Enable-ComputerRestore -Drive "C:\"
  	Checkpoint-Computer -Description "RestorePoint1" -RestorePointType "MODIFY_SETTINGS"
}
  
##########
# Parse parameters and apply tweaks
##########

# Normalize path to preset file
$preset = ""
$PSCommandArgs = $args
If ($args -And $args[0].ToLower() -eq "-preset") {
	$preset = Resolve-Path $($args | Select-Object -Skip 1)
	$PSCommandArgs = "-preset `"$preset`""
}

# Load function names from command line arguments or a preset file
If ($args) {
	$tweaks = $args
	If ($preset) {
		$tweaks = Get-Content $preset -ErrorAction Stop | ForEach { $_.Trim() } | Where { $_ -ne "" -and $_[0] -ne "#" }
	}
}

# Call the desired tweak functions
$tweaks | ForEach { Invoke-Expression $_ }