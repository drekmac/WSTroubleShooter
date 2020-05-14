<#
.SYNOPSIS
Used to run a lot of different troubleshooting commands on a workstation.
.DESCRIPTION
Used to run a lot of different troubleshooting commands on a workstation.
.EXAMPLE
Troubleshooter.ps1
Literally just run it
#>
<#
Changelog
V1.4    ConfigMgr section wasn't pulling certain info, removed BitLocker data and everything else righted itself.
V1.3    Changed some formatting to work in Powershell 7, still doesn't work in Powershell 7, also added TPM OwnerAuth
V1.2    I apparently didn't document whatever I changed here, I think it was more reorganization and nothing functional
V1.1    Added in help references and did some organization
V1.0    Initial product
#>
# Init PowerShell Gui
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
#Temp File for Reports
$tempfile = New-TemporaryFile
# Create a new form
[System.Windows.Forms.Application]::EnableVisualStyles()
# Styling
$MSSS13 = [System.Drawing.Font]::new('Microsoft Sans Serif',13)
$MSSS7 = [System.Drawing.Font]::new('Microsoft Sans Serif',7)
$lightgray = [System.Drawing.Color]::LightGray
$darkgray = [System.Drawing.Color]::FromArgb(56,56,56)
$darkergray = [System.Drawing.Color]::FromArgb(30,30,30)
$black = [System.Drawing.Color]::Black
#Main Window
$GetInfoForm = New-Object system.Windows.Forms.Form
$GetInfoForm.ClientSize = [System.Drawing.Size]::new(800,350)
$GetInfoForm.text = "Troubleshooter"
$GetInfoForm.BackColor = $darkergray
$GetInfoForm.TopMost = $false
#Title
$Title = New-Object system.Windows.Forms.Label
$Title.text = "Workstation Troubleshooter"
$Title.AutoSize = $true
$Title.width = 25
$Title.height = 10
$Title.location = New-Object System.Drawing.Point(20,20)
$Title.Font = $MSSS13
$Title.ForeColor = $LightGray
#Textbox for entering computer name, with my computer name as default to make testing easier
$CompName = New-Object System.Windows.Forms.TextBox
$CompName.Text = "W3XTZFH2"
$CompName.Height = 100
$CompName.Width = 170
$CompName.AutoSize = $true
$CompName.Location = New-Object System.Drawing.Point(20,45)
$CompName.BackColor = $darkgray
$CompName.ForeColor = $lightgray
#Output box where returned info is displayed
$outputBox = New-Object System.Windows.Forms.TextBox
$outputBox.Location = New-Object System.Drawing.Point(20,75)
$outputBox.Size = New-Object System.Drawing.Size(300,180)
$outputBox.MultiLine = $True
$outputBox.BackColor = $darkgray
$outputBox.ForeColor = $lightgray
#Quick info section
$IPbox = New-Object System.Windows.Forms.Label
$IPbox.AutoSize = $true
$IPbox.Location = New-Object System.Drawing.Point(200,45)
$IPbox.ForeColor = $lightgray
$ModelBox = New-Object System.Windows.Forms.Label
$ModelBox.AutoSize = $true
$ModelBox.Location = New-Object System.Drawing.Point(280,45)
$ModelBox.ForeColor = $lightgray
$OSBox = New-Object System.Windows.Forms.Label
$OSBox.AutoSize = $true
$OSBox.Location = New-Object System.Drawing.Point(360,45)
$OSBox.ForeColor = $lightgray
$TPMBox = New-Object System.Windows.Forms.Label
$TPMBox.AutoSize = $true
$TPMBox.Location = New-Object System.Drawing.Point(450,45)
$TPMBox.ForeColor = $lightgray
$ProtBox = New-Object System.Windows.Forms.Label
$ProtBox.AutoSize = $true
$ProtBox.Location = New-Object System.Drawing.Point(520,45)
$ProtBox.ForeColor = $lightgray
$EncBox = New-Object System.Windows.Forms.Label
$EncBox.AutoSize = $true
$EncBox.Location = New-Object System.Drawing.Point(590,45)
$EncBox.ForeColor = $lightgray
#Label for explaining the buttons to install tools on local machine
$LocalLabel = New-Object System.Windows.Forms.Label
$LocalLabel.text = "Install necessary modules on your local computer to pull info about remote computer."
$LocalLabel.AutoSize = $true
$LocalLabel.width = 25
$LocalLabel.height = 10
$LocalLabel.location = New-Object System.Drawing.Point(20,265)
$LocalLabel.ForeColor = $lightgray
#Beginning of main button block
###############-----Column A-----###############
#A1
$PingButton = New-Object System.Windows.Forms.Button
$PingButton.BackColor = $lightgray
$PingButton.Text = "Connection Test"
$PingButton.Width = 90
$PingButton.Height = 30
$PingButton.Location = New-Object System.Drawing.Point(335,75)
$PingButton.ForeColor = $black
$PingButton.Font = $MSSS7
$PingButton.Add_Click(
    {
        $outputBox.Text = "Pinging computer...."
        $ping = Get-Ping -CompName $CompName.Text
        if ($ping)
        {
            $outputBox.AppendText("`r`nPing Successful")
            $IPbox.Text = $ping.IPv4Address.IPAddressToString[0]
            $outputBox.AppendText("`r`nChecking Info on Computer....")
            try 
            {
                $info = Get-Info -CompName $CompName.Text            
                $ModelBox.Text = $info.Model
                $OSBox.Text = "Win " + $info.OS_Ver
                $TPMbox.Text = "TPM:" + $info.TPM_Present
                $ProtBox.Text = "BitLock:" + $info.Protection
                $EncBox.Text = "C:" + $info.BitLockerStatus
                $outputBox.AppendText("`r`nComputer data gathered")
            }
            catch 
            {
                $outputBox.AppendText("`r`nSomething went wrong")
            }
            
            
        }
        else 
        {
            $outputBox.Text = "Ping Unsuccessful"
            $IPbox.Text = ""
        }
    }
)
#A2
$PCButton = New-Object System.Windows.Forms.Button
$PCButton.BackColor = $lightgray
$PCButton.Text = "PC Info"
$PCButton.Width = 90
$PCButton.Height = 30
$PCButton.Location = New-Object System.Drawing.Point(335,105)
$PCButton.ForeColor = $black
$PCButton.Font = $MSSS7
$PCButton.Add_Click(
    {
        try 
        {
            $info = Get-Info -CompName $CompName.Text
            Add-Content -Path $tempfile.FullName -Value '---------- Info From Computer Itself ----------'
            $info | Format-List | Out-String | Add-Content -Path $tempfile.FullName
            Notepad $tempfile
            $outputBox.Text = ""
        }
        catch 
        {
                $outputBox.Text = "Something went wrong, maybe check ping?"
        }
    }
)
#A3
$ADButton = New-Object System.Windows.Forms.Button
$ADButton.BackColor = $lightgray
$ADButton.Text = "AD Info"
$ADButton.Width = 90
$ADButton.Height = 30
$ADButton.Location = New-Object System.Drawing.Point(335,135)
$ADButton.ForeColor = $black
$ADButton.Font = $MSSS7
$ADButton.Add_Click(
    {
        $outbox = ""
        if (!(Get-Module -ListAvailable -Name activedirectory))
        {
            $outbox += "Please install module activedirectory from RSAT"
        } 
        else
        {
            $outbox += "Module activedirectory installed, proceeding with computer AD check"
        }
        $outputBox.Text = $outbox
        $AD = Get-ADInfo -CompName $CompName.Text
        Add-Content -Path $tempfile.FullName -Value '---------- AD Info ----------'
        $AD | Select-Object Name,@{Name="LastLogonTimeStamp";Expression={([datetime]::FromFileTime($_.LastLogonTimeStamp))}},Description,Created,Modified,Deleted,Enabled,OperatingSystem,OperatingSystemVersion,PasswordLastSet,IPv4address,CanonicalName | Format-List | Out-String | Add-Content -Path $tempfile.FullName
        Add-Content -Path $tempfile.FullName -Value "---------- Group Membership ----------`n"
        $AD.MemberOf | Format-List | Out-String | Add-Content -Path $tempfile.FullName
        Notepad $tempfile
    }
)
#A4
$SCCMButton = New-Object System.Windows.Forms.Button
$SCCMButton.BackColor = $lightgray
$SCCMButton.Text = "SCCM Info"
$SCCMButton.Width = 90
$SCCMButton.Height = 30
$SCCMButton.Location = New-Object System.Drawing.Point(335,165)
$SCCMButton.ForeColor = $black
$SCCMButton.Font = $MSSS7
$SCCMButton.Add_Click(
    {
        if (!(Get-Module -ListAvailable -Name sqlserver)) 
        {
            $outputBox.Text = "Please install the sqlserver module. (Install-Module -Name sqlserver)"
            return
        }
        else
        {
            $outputBox.Text = "Module sqlserver installed, proceeding with computer SCCM check"
            $SCCMhardware = Get-SCCMdata -CompName $CompName.Text -query "Hardware"
            $SCCMCollections = Get-SCCMdata -CompName $CompName.Text -query "Collection"
            Add-Content -Path $tempfile.FullName -Value "---------- SCCM Data ----------`r`nSCCM Data is only accurate as of the last hardware scan date!"
            $SCCMhardware | Format-List | Out-String | Add-Content -Path $tempfile.FullName
            Add-Content -Path $tempfile.FullName -Value '---------- Maintenance Windows ----------'
            $SCCMCollections | Where-Object Maint_Enabled -EQ $true | Select-Object CollectionID,MaintWindow_Name,MaintWindowDesc,MaintStartTime,MaintDuration,MaintRecurrance,Maint_Enabled,MaintWind_Type | Format-List | Out-String | Add-Content -Path $tempfile.FullName
            Add-Content -Path $tempfile.FullName -Value '---------- Collection Membership ----------'
            $SCCMCollections | Select-Object CollectionID,Maint_Enabled,Collection_Name | Format-Table | Out-String | Add-Content -Path $tempfile.FullName            
            Notepad $tempfile  
        }
      
    }
)
#A5
$PSSessionButton = New-Object System.Windows.Forms.Button
$PSSessionButton.BackColor = $lightgray
$PSSessionButton.Text = "PSSession"
$PSSessionButton.Width = 90
$PSSessionButton.Height = 30
$PSSessionButton.Location = New-Object System.Drawing.Point(335,195)
$PSSessionButton.ForeColor = $black
$PSSessionButton.Font = $MSSS7
$PSSessionButton.Add_Click(
    {
        try 
        {
            $PCname = $CompName.Text
            Start-Process -FilePath 'PowerShell.exe' -ArgumentList '-NoExit',"-command `"Enter-PSSession -ComputerName $PCname`""
        }
        catch 
        {
            $outputBox.Text = "Error, test ping maybe?"
        }
    }
)
#A6
$RDP = New-Object System.Windows.Forms.Button
$RDP.BackColor = $lightgray
$RDP.Text = "RDP"
$RDP.Width = 90
$RDP.Height = 30
$RDP.Location = New-Object System.Drawing.Point(335,225)
$RDP.ForeColor = $black
$RDP.Font = $MSSS7
$RDP.Add_Click(
    {
        try 
        {
            $PC = $compname.text
            mstsc /v:$PC
        }
        catch 
        {
            $outputBox.Text = "Something went wrong"
        }
    }
)
###############-----Column B-----###############
#B1
$SCCMCheckButton = New-Object System.Windows.Forms.Button
$SCCMCheckButton.BackColor = $lightgray
$SCCMCheckButton.Text = "Client Check"
$SCCMCheckButton.Width = 90
$SCCMCheckButton.Height = 30
$SCCMCheckButton.Location = New-Object System.Drawing.Point(435,75)
$SCCMCheckButton.ForeColor = $black
$SCCMCheckButton.Font = $MSSS7
$SCCMCheckButton.Add_Click(
    {
        try 
        {
            $software = Get-CimInstance Win32Reg_AddRemovePrograms -ComputerName $CompName.Text | Where-Object DisplayName -EQ "Configuration Manager Client"
            if (!$software) 
            {
                $outputBox.Text = "Can't find Configmgr Client"    
            }
            else 
            {
                $outputBox.Text = $software | Out-String
                $outputBox.AppendText("Client Seems to be installed.")
            }
        }
        catch 
        {
                $outputBox.Text = "Something went wrong, maybe check ping?"
        }
       
    }
)
#B2
$InstallClient = New-Object System.Windows.Forms.Button
$InstallClient.BackColor = $lightgray
$InstallClient.Text = "Install Client"
$InstallClient.Width = 90
$InstallClient.Height = 30
$InstallClient.Location = New-Object System.Drawing.Point(435,105)
$InstallClient.ForeColor = $black
$InstallClient.Font = $MSSS7
$InstallClient.Add_Click(
    {
        try
        {
            $name = $compName.Text
            Copy-Item -Path '\\wdc-vsdsps1p01\SCCMClient\ccmsetup.exe' -Destination "\\$name\c$\Windows\CCMsetup" 
            Invoke-Command -computername $name -ScriptBlock { Start-job -ScriptBlock { & cmd.exe /c "c:\Windows\CCMsetup\ccmsetup.exe SMSSITECODE=PS1 FSP=WDC-VSDFSPR1P01 CCMENABLELOGGING=TRUE CCMLOGLEVEL=0 CCMLOGMAXSIZE=5242880 CCMLOGMAXHISTORY=5"}}
            CMTrace.exe "\\$name\c$\Windows\ccmsetup\logs\ccmsetup.log"
            $outputBox.Text = "Install began, may take a few minutes so be patient. Cmtrace should have opened to the computer's ccmsetup.log. If not, navigate to \\$name\c$\Windows\ccmsetup\logs\"
        }
        catch 
        {
                $outputBox.Text = "Something went wrong, maybe check ping?"
        }
    }
)
#B3
$ForceInstallClient = New-Object System.Windows.Forms.Button
$ForceInstallClient.BackColor = $lightgray
$ForceInstallClient.Text = "Force Install"
$ForceInstallClient.Width = 90
$ForceInstallClient.Height = 30
$ForceInstallClient.Location = New-Object System.Drawing.Point(435,135)
$ForceInstallClient.ForeColor = $black
$ForceInstallClient.Font = $MSSS7
$ForceInstallClient.Add_Click(
    {
        try
        {
            $name = $compName.Text
            Copy-Item -Path '\\wdc-vsdsps1p01\SCCMClient\ccmsetup.exe' -Destination "\\$name\c$\Windows\CCMsetup" 
            Invoke-Command -computername $name -ScriptBlock { Start-job -ScriptBlock { & cmd.exe /c "c:\Windows\CCMsetup\ccmsetup.exe /forceinstall SMSSITECODE=PS1 FSP=WDC-VSDFSPR1P01 CCMENABLELOGGING=TRUE CCMLOGLEVEL=0 CCMLOGMAXSIZE=5242880 CCMLOGMAXHISTORY=5"}}
            CMTrace.exe "\\$name\c$\Windows\ccmsetup\logs\ccmsetup.log"
            $outputBox.Text = "Install began, may take a few minutes so be patient. Cmtrace should have opened to the computer's ccmsetup.log. If not, navigate to \\$name\c$\Windows\ccmsetup\logs\"
        }
        catch 
        {
            $outputBox.Text = "Something went wrong, maybe check ping?"
        }     
    }
)
#B4
$LogButton = New-Object System.Windows.Forms.Button
$LogButton.BackColor = $lightgray
$LogButton.Text = "Logs"
$LogButton.Width = 90
$LogButton.Height = 30
$LogButton.Location = New-Object System.Drawing.Point(435,165)
$LogButton.ForeColor = $black
$LogButton.Font = $MSSS7
$LogButton.Add_Click(
    {
        $outputBox.Text = "Opening \\$name\c$\Windows\ccm\logs\"
        $name = $CompName.Text
        try 
        {
            Invoke-Item "\\$name\c$\Windows\ccm\logs\"
            $outputBox.Text = "\\$name\c$\Windows\ccm\logs\ opened."
        }
        catch 
        {
            $outputBox.Text = "\\$name\c$\Windows\ccm\logs\ failed to open."
        }
    }
)
#B5
$RMButton = New-Object System.Windows.Forms.Button
$RMButton.BackColor = $lightgray
$RMButton.Text = "Remove Profile"
$RMButton.Width = 90
$RMButton.Height = 30
$RMButton.Location = New-Object System.Drawing.Point(435,195)
$RMButton.ForeColor = $black
$RMButton.Font = $MSSS7
$RMButton.Add_Click(
    {
        try 
        {
            $username = $env:UserName
            get-ciminstance -ClassName Win32_UserProfile -computername $compname | Where-Object localpath -eq "c:\users\$username" | Remove-CIMinstance
        }
        catch
        {
            $outputBox.Text = "Something went wrong"
        }
    }
)
#B6
$PingDashTButton = New-Object System.Windows.Forms.Button
$PingDashTButton.BackColor = $lightgray
$PingDashTButton.Text = "Ping -T"
$PingDashTButton.Width = 90
$PingDashTButton.Height = 30
$PingDashTButton.Location = New-Object System.Drawing.Point(435,225)
$PingDashTButton.ForeColor = $black
$PingDashTButton.Font = $MSSS7
$PingDashTButton.Add_Click(
    {
        try 
        {
            $PCname = $CompName.Text
            Start-Process -FilePath 'PowerShell.exe' -ArgumentList '-NoExit',"-command `"Ping -t $PCname`""
        }
        catch 
        {
            $outputBox.Text = "Something went wrong"
        }
    }
)
###############-----Column C-----###############
#C1
$CCMEvalButton = New-Object System.Windows.Forms.Button
$CCMEvalButton.BackColor = $lightgray
$CCMEvalButton.Text = "CCM Eval"
$CCMEvalButton.Width = 90
$CCMEvalButton.Height = 30
$CCMEvalButton.Location = New-Object System.Drawing.Point(535,75)
$CCMEvalButton.ForeColor = $black
$CCMEvalButton.Font = $MSSS7
$CCMEvalButton.Add_Click(
    {
        $outputBox.Text = "Opening \\$name\c$\Windows\ccm\logs\"
        $name = $CompName.Text
        try 
        {
            CMTrace.exe "\\$name\c$\Windows\ccm\logs\ccmeval.log"
            Invoke-Command -computername $name -ScriptBlock { Start-job -ScriptBlock { & cmd.exe /c "C:\Windows\ccm\CcmEval.exe"}}
            $outputBox.Text = "Ccmeval begun"
        }
        catch 
        {
            $outputBox.Text = "Something went wrong"
        }
    }
)
#C2
$CCMRepairButton = New-Object System.Windows.Forms.Button
$CCMRepairButton.BackColor = $lightgray
$CCMRepairButton.Text = "CCM Repair"
$CCMRepairButton.Width = 90
$CCMRepairButton.Height = 30
$CCMRepairButton.Location = New-Object System.Drawing.Point(535,105)
$CCMRepairButton.ForeColor = $black
$CCMRepairButton.Font = $MSSS7
$CCMRepairButton.Add_Click(
    {
        $outputBox.Text = "Opening \\$name\c$\Windows\ccm\logs\"
        $name = $CompName.Text
        try 
        {
            CMTrace.exe "\\$name\c$\Windows\ccm\logs\ccmrepair.log"
            Invoke-Command -computername $name -ScriptBlock { Start-job -ScriptBlock { cmd.exe /c "C:\Windows\ccm\CcmRepair.exe"}}
            $outputBox.Text = "CcmRepair begun"
        }
        catch 
        {
            $outputBox.Text = "Something went wrong"
        }
    }
)
#C3
$CCMRestartButton = New-Object System.Windows.Forms.Button
$CCMRestartButton.BackColor = $lightgray
$CCMRestartButton.Text = "CCM Service Restart"
$CCMRestartButton.Width = 90
$CCMRestartButton.Height = 30
$CCMRestartButton.Location = New-Object System.Drawing.Point(535,135)
$CCMRestartButton.ForeColor = $black
$CCMRestartButton.Font = $MSSS7
$CCMRestartButton.Add_Click(
    {
        $outputBox.Text = "Opening \\$name\c$\Windows\ccm\logs\"
        $name = $CompName.Text
        try 
        {
            CMTrace.exe "\\$name\c$\Windows\ccm\logs\ccmrestart.log"
            Invoke-Command -computername $name -ScriptBlock {Restart-Service CcmExec}
            $outputBox.Text = "CcmExec Restarted"
        }
        catch 
        {
            $outputBox.Text = "Something went wrong"
        }
    }
)
#C4
$SoftwareCheckButton = New-Object System.Windows.Forms.Button
$SoftwareCheckButton.BackColor = $lightgray
$SoftwareCheckButton.Text = "PS Installed Software"
$SoftwareCheckButton.Width = 90
$SoftwareCheckButton.Height = 30
$SoftwareCheckButton.Location = New-Object System.Drawing.Point(535,165)
$SoftwareCheckButton.ForeColor = $black
$SoftwareCheckButton.Font = $MSSS7
$SoftwareCheckButton.Add_Click(
    {
        try 
        {
            $software = Get-CimInstance Win32Reg_AddRemovePrograms -ComputerName $CompName.Text | Select-Object DisplayName,Version,Publisher | Sort-Object DisplayName | Format-Table -AutoSize
            if (!$software) 
            {
                $outputBox.Text = "Error, no data found."    
            }
            else 
            {
                Add-Content -Path $tempfile.FullName -Value "---------- Installed Software ----------`r`n"
                Add-Content -Path $tempfile.FullName -Value $CompName.Text
                $software | Out-String | Add-Content -Path $tempfile.FullName
                Notepad $tempfile
                $outputBox.AppendText("Software installed added to temp file.")
            }
        }
        catch 
        {
                $outputBox.Text = "Something went wrong, maybe check ping?"
        }
       
    }
)
#C5
$SCCMsoftwareButton = New-Object System.Windows.Forms.Button
$SCCMsoftwareButton.BackColor = $lightgray
$SCCMsoftwareButton.Text = "SCCM Installed Software"
$SCCMsoftwareButton.Width = 90
$SCCMsoftwareButton.Height = 30
$SCCMsoftwareButton.Location = New-Object System.Drawing.Point(535,195)
$SCCMsoftwareButton.ForeColor = $black
$SCCMsoftwareButton.Font = $MSSS7
$SCCMsoftwareButton.Add_Click(
    {
        if (!(Get-Module -ListAvailable -Name sqlserver)) 
        {
            $outputBox.Text = "Please install the sqlserver module. (Install-Module -Name sqlserver)"
            return
        }
        else
        {            
            $outputBox.Text = "Module sqlserver installed, proceeding with computer SCCM software check"
            Add-Content -Path $tempfile.FullName -Value "---------- SCCM Software Data ----------`r`nSCCM Data is only accurate as of the last scan date!"
            $SCCMsoftware = Get-SCCMdata -CompName $CompName.Text -query Software
            $SCCMsoftware | Format-Table | Out-String | Add-Content -Path $tempfile.FullName       
            Notepad $tempfile  
        }
      
    }
)
#C6
$CLIButton = New-Object System.Windows.Forms.Button
$CLIButton.BackColor = $lightgray
$CLIButton.Text = "Client Center"
$CLIButton.Width = 90
$CLIButton.Height = 30
$CLIButton.Location = New-Object System.Drawing.Point(535,225)
$CLIButton.ForeColor = $black
$CLIButton.Font = $MSSS7
$CLIButton.Add_Click(
    {
        try 
        {
            $PC = $compname.text
            $ClientCenter = "C:\Program Files\Client Center for Configuration Manager\SCCMCliCtrWPF.exe"
            if(Test-Path $ClientCenter)
            {
                & $ClientCenter $PC
            }
            else
            {
                $outputBox.Text = "Client Center is not installed"        
            }
            
        }
        catch 
        {
            $outputBox.Text = "Something went wrong, make sure Client Center is installed"
        }
    }
)
#C7
$NomadLog = New-Object System.Windows.Forms.Button
$NomadLog.BackColor = $lightgray
$NomadLog.Text = "Nomad Logs"
$NomadLog.Width = 90
$NomadLog.Height = 30
$NomadLog.Location = New-Object System.Drawing.Point(535,255)
$NomadLog.ForeColor = $black
$NomadLog.Font = $MSSS7
$NomadLog.Add_Click(
    {
        $outputBox.Text = "Opening \\$name\c$\Windows\ccm\logs\NomadBranch.log"
        $name = $CompName.Text
        try 
        {
            CMTrace.exe "\\$name\c$\Windows\ccm\logs\NomadBranch.log"
            $outputBox.Text = "\\$name\c$\Windows\ccm\logs\NomadBranch.log opened."
        }
        catch 
        {
            $outputBox.Text = "\\$name\c$\Windows\ccm\logs\NomadBranch.log failed to open."
        }
    }
)
###############-----Column D-----###############
#D1
$MachinePolicy = New-Object System.Windows.Forms.Button
$MachinePolicy.BackColor = $lightgray
$MachinePolicy.Text = "Machine Policy Retrieval"
$MachinePolicy.Width = 120
$MachinePolicy.Height = 30
$MachinePolicy.Location = New-Object System.Drawing.Point(635,75)
$MachinePolicy.ForeColor = $black
$MachinePolicy.Font = $MSSS7
$MachinePolicy.Add_Click(
    {
        $outputBox.Text = "Retrieving Machine Policy"
        $name = $CompName.Text
        try 
        {
            Invoke-WMIMethod -ComputerName $name -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000021}"
            $outputBox.Text = "Machine Policy Retrieval begun"
        }
        catch 
        {
            $outputBox.Text = "Something went wrong"
        }
    }
)
#D2
$MachinePolicyEval = New-Object System.Windows.Forms.Button
$MachinePolicyEval.BackColor = $lightgray
$MachinePolicyEval.Text = "Machine Policy Evaluation"
$MachinePolicyEval.Width = 120
$MachinePolicyEval.Height = 30
$MachinePolicyEval.Location = New-Object System.Drawing.Point(635,105)
$MachinePolicyEval.ForeColor = $black
$MachinePolicyEval.Font = $MSSS7
$MachinePolicyEval.Add_Click(
    {
        $outputBox.Text = "Evaluating Machine Policy"
        $name = $CompName.Text
        try 
        {
            Invoke-WMIMethod -ComputerName $name -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000022}"
            $outputBox.Text = "Machine Policy Evaluation begun"
        }
        catch 
        {
            $outputBox.Text = "Something went wrong"
        }
    }
)
#D3
$ScanAppButton = New-Object System.Windows.Forms.Button
$ScanAppButton.BackColor = $lightgray
$ScanAppButton.Text = "App Deployment Scan"
$ScanAppButton.Width = 120
$ScanAppButton.Height = 30
$ScanAppButton.Location = New-Object System.Drawing.Point(635,135)
$ScanAppButton.ForeColor = $black
$ScanAppButton.Font = $MSSS7
$ScanAppButton.Add_Click(
    {
        $outputBox.Text = "Running App Deployment Scan"
        $name = $CompName.Text
        try 
        {
            Invoke-WMIMethod -ComputerName $name -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000121}"
            $outputBox.Text = "Application Deployment Scan begun"
        }
        catch 
        {
            $outputBox.Text = "Something went wrong"
        }
    }
)
#D4
$HardwareInventoryScan = New-Object System.Windows.Forms.Button
$HardwareInventoryScan.BackColor = $lightgray
$HardwareInventoryScan.Text = "Hardware Inventory Scan"
$HardwareInventoryScan.Width = 120
$HardwareInventoryScan.Height = 30
$HardwareInventoryScan.Location = New-Object System.Drawing.Point(635,165)
$HardwareInventoryScan.ForeColor = $black
$HardwareInventoryScan.Font = $MSSS7
$HardwareInventoryScan.Add_Click(
    {
        $outputBox.Text = "Performing a hardware inventory scan"
        $name = $CompName.Text
        try 
        {
            Invoke-WMIMethod -ComputerName $name -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000001}"
            $outputBox.Text = "Hardware Inventory Scan Begun"
        }
        catch 
        {
            $outputBox.Text = "Something went wrong"
        }
    }
)
#D5
$gpupdate = New-Object System.Windows.Forms.Button
$gpupdate.BackColor = $lightgray
$gpupdate.Text = "Gpupdate"
$gpupdate.Width = 120
$gpupdate.Height = 30
$gpupdate.Location = New-Object System.Drawing.Point(635,195)
$gpupdate.ForeColor = $black
$gpupdate.Font = $MSSS7
$gpupdate.Add_Click(
    {
        $outputBox.Text = "Executing gpupdate....."
        try 
        {
            gpupdate
            $outputBox.AppendText("`r`ngpupdate done. May require a restart to complete.")
        }
        catch 
        {
            $outputBox.Text = "Something went wrong"
        }
    }
)
#D6
$Reboot = New-Object System.Windows.Forms.Button
$Reboot.BackColor = $lightgray
$Reboot.Text = "Force Reboot"
$Reboot.Width = 120
$Reboot.Height = 30
$Reboot.Location = New-Object System.Drawing.Point(635,225)
$Reboot.ForeColor = $black
$Reboot.Font = $MSSS7
$Reboot.Add_Click(
    {
        $outputBox.Text = "Executing shutdown -r -t 0...."
        try 
        {
            Reboot
            $outputBox.AppendText("`r`nShutdown -r -t 0 command sent.")
        }
        catch 
        {
            $outputBox.Text = "Something went wrong"
        }
    }
)
###############-----Tool Install Button Group-----###############
#1
$RSATButton = New-Object System.Windows.Forms.Button
$RSATButton.BackColor = $lightgray
$RSATButton.Text = "Install RSAT"
$RSATButton.Width = 90
$RSATButton.Height = 30
$RSATButton.Location = New-Object System.Drawing.Point(20,280)
$RSATButton.ForeColor = $black
$RSATButton.Font = $MSSS7
$RSATButton.Add_Click(
    {
        try 
        {
            $outputBox.Text = "Installing RSAT"
            $currentWU = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" | Select-Object -ExpandProperty UseWUServer
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Value 0
            Restart-Service "wuauserv"
            $apps = Get-WindowsCapability -Name "RSAT*" -Online
            foreach($app in $apps)
            {
                Add-WindowsCapability -Online -Name $app.Name
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Value $currentWU
            Restart-Service "wuauserv"
            $outputBox.Text = "RSAT Installed"
        }
        catch 
        {
                $outputBox.Text = "Something went wrong, maybe install manually."
        }
    }
)
#2
$SQLButton = New-Object System.Windows.Forms.Button
$SQLButton.BackColor = $lightgray
$SQLButton.Text = "Install SQL Module"
$SQLButton.Width = 90
$SQLButton.Height = 30
$SQLButton.Location = New-Object System.Drawing.Point(110,280)
$SQLButton.ForeColor = $black
$SQLButton.Font = $MSSS7
$SQLButton.Add_Click(
    {
        if (!(Get-Module -ListAvailable -Name sqlserver)) {
            try 
            {
                $outputBox.Text = "Installing Module sqlserver"
                Install-Module sqlserver -Force
                $outputBox.Text = "Module sqlserver Installed"
            }
            catch 
            {
                    $outputBox.Text = "Something went wrong, maybe install manually."
            }
        } else {
            $outputBox.Text = "SQL Module already installed"
            Update-Module sqlserver -Force
        } 
    }
)
#3
$CLIinstall = New-Object System.Windows.Forms.Button
$CLIinstall.BackColor = $lightgray
$CLIinstall.Text = "Download Client Center"
$CLIinstall.Width = 90
$CLIinstall.Height = 30
$CLIinstall.Location = New-Object System.Drawing.Point(200,280)
$CLIinstall.ForeColor = $black
$CLIinstall.Font = $MSSS7
$CLIinstall.Add_Click(
    {
        try 
        {
            $outputBox.Text = "Opening Browser"
            Start-Process "https://github.com/rzander/sccmclictr/releases"
            $outputBox.Text = "Browser Opened, please download and install if needed"
        }
        catch 
        {
                $outputBox.Text = "Something went wrong, maybe install manually."
        }
    }
)
###############-----Functions-----###############
function Get-Ping {
    param (
        [Parameter(Mandatory)]
        [string]$CompName
    )
    $ping = Test-Connection $CompName
    return $ping
}
function get-adinfo {
    param (
        [Parameter(Mandatory)]
        [string]$CompName
    )
    $properties =@(
    'Name'
    'CanonicalName'
    'Created'
    'Description'
    'Deleted'
    'DistinguishedName'
    'Enabled'
    'IPv4Address'
    'LastLogonTimestamp'
    'MemberOf'
    'Modified'
    'OperatingSystem'
    'OperatingSystemVersion'
    'PasswordLastSet'
    )
    $AD = get-adcomputer -Identity $compName -Properties $properties
    return $AD
}
function Get-Info {
    param (
        [Parameter(Mandatory)]
        [string]$CompName
    )
    $results = New-Object psobject
    $results | Add-Member -NotePropertyName "Name" -NotePropertyValue $CompName
    if (Test-Connection -ComputerName $CompName -Quiet -Count 2)
    {        
        $BIOS = Get-CimInstance -ClassName Win32_Bios -ComputerName $CompName
        $bitlocker = Invoke-command -computername $CompName -ScriptBlock {Get-BitLockerVolume -MountPoint "C:"}
        #$key = $bitlocker.keyprotector.RecoveryPassword | Where-Object {$bitlocker.keyprotector.keyprotectorType -EQ "RecoveryPassword"}
        $key = Invoke-Command -computername $CompName -ScriptBlock {((Get-BitLockerVolume -MountPoint C).KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword').RecoveryPassword}
        $CompSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $CompName
        $TPM = Get-ciminstance -class Win32_Tpm -namespace root\CIMV2\Security\MicrosoftTpm -ComputerName $CompName
        $TPM2 = Invoke-command -computername $CompName -ScriptBlock {Get-Tpm}
        $OS = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $CompName
        $Disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ComputerName $CompName
        $CPUs = $CompSystem.NumberOfProcessors
        $Cores = $CompSystem.NumberOfLogicalProcessors
        $HDD = "{0:N2}" -f ($Disk.Size/1GB) + " GB"
        $freedisk = "{0:N2}" -f ($disk.FreeSpace/1GB) + " GB"
        $RAM = "{0:N2}" -f ($CompSystem.TotalPhysicalMemory/1GB) + "GB"        
        $Uptime = ((get-date) - (Get-CimInstance Win32_OperatingSystem -ComputerName $CompName).LastBootUpTime).TotalHours
        $results | Add-Member -NotePropertyName "Ping" -NotePropertyValue $true
        $results | Add-Member -NotePropertyName "BIOS" -NotePropertyValue $BIOS.SMBIOSBIOSVersion
        $results | Add-Member -NotePropertyName  "Model" -NotePropertyValue $CompSystem.Model
        $results | Add-Member -NotePropertyName  "OS" -NotePropertyValue $OS.Caption
        $results | Add-Member -NotePropertyName  "OS_Ver" -NotePropertyValue $OS.Version
        $results | Add-Member -NotePropertyName "TPM_Present" -NotePropertyValue $tpm.IsEnabled_InitialValue
        $results | Add-Member -NotePropertyName "TPM_Ready" -NotePropertyValue $tpm.IsActivated_InitialValue
        $results | Add-Member -NotePropertyName "TPM_Owned" -NotePropertyValue $tpm.IsOwned_InitialValue
        $results | Add-Member -NotePropertyName "TPM_Full_Ver" -NotePropertyValue $tpm.ManufacturerVersionFull20
        $results | Add-Member -NotePropertyName "TPM_Ver" -NotePropertyValue $tpm.ManufacturerVersion
        $results | Add-Member -NotePropertyName "TPM_OwnerAuth" -NotePropertyValue $tpm2.ownerauth
        $results | Add-Member -NotePropertyName "BitLockerStatus" -NotePropertyValue $bitlocker.VolumeStatus
        $results | Add-Member -NotePropertyName "Protection" -NotePropertyValue $bitlocker.ProtectionStatus
        $results | Add-Member -NotePropertyName "Key" -NotePropertyValue $key
        $results | Add-Member -NotePropertyName "Uptime(hours)" -NotePropertyValue $uptime
        $results | Add-Member -NotePropertyName "CPUs" -NotePropertyValue $CPUs
        $results | Add-Member -NotePropertyName "Cores" -NotePropertyValue $Cores
        $results | Add-Member -NotePropertyName "C:_Total" -NotePropertyValue $HDD
        $results | Add-Member -NotePropertyName "C:_Free" -NotePropertyValue $freedisk
        $results | Add-Member -NotePropertyName "RAM_Total" -NotePropertyValue $RAM        
    }
    else 
    {
        $results | Add-Member -NotePropertyName "Ping" -NotePropertyValue $false
    }
    return $results
}
function Get-SCCMdata {
    param (
        [Parameter(Mandatory)]
        [string]$CompName,
        [string]$query 
    )
    $results = New-Object psobject
    $results | Add-Member -NotePropertyName "Name" -NotePropertyValue $CompName
    $results | Add-Member -NotePropertyName "Disclaimer" -NotePropertyValue "Data only as acurate as of last hardware scan"
    $SQLInstance = "wdc-vsdps1dbp02"
    $SQLDatabase = "CM_PS1"
    if($query -eq "Hardware")
    {
        $select = "
            select
            vrs.Name0,
            stat.LastHWScan,
            bios.SMBIOSBIOSVersion0,
            comp.Model0,
            os.Caption0,
            vrs.Build01,
            CASE
                when tpm.IsEnabled_InitialValue0 = 1 then 'True'
                else 'False'
            END AS TPM_Present,
            CASE
                when tpm.IsActivated_InitialValue0 = 1 then 'True'
                else 'False'
            END AS TPM_Ready,
            CASE 
                when tpm.IsOwned_InitialValue0 = 1 then 'True'
                else 'False'
            END AS TPM_Owned,
            tpm.ManufacturerVersion0,
            tpm.ManufacturerVersionFull200,
            os.LastBootUpTime0,
            comp.NumberOfProcessors0,
            disc.Size0 AS FullDiskSize_GB,
            disc.FreeSpace0 AS FreeDiskSize_GB,
            mem.TotalPhysicalMemory00
            from v_R_System vrs
            join v_GS_WORKSTATION_STATUS stat on vrs.ResourceID = stat.ResourceID
            join v_GS_PC_BIOS bios on bios.ResourceID = vrs.ResourceID
            join v_GS_COMPUTER_SYSTEM comp on vrs.ResourceID = comp.ResourceID
            join v_GS_OPERATING_SYSTEM OS on vrs.ResourceID = os.ResourceID
            join v_GS_TPM TPM on vrs.ResourceID = tpm.ResourceID
            join v_GS_PROCESSOR CPU on vrs.ResourceID = cpu.ResourceID
            join v_GS_LOGICAL_DISK disc on vrs.ResourceID = disc.ResourceID
            join PC_Memory_DATA mem on vrs.ResourceID = mem.MachineID
            where 
            disc.DeviceID0 = 'C:' AND
            vrs.Name0 = '$compname'
            "
    }
    if ($query -eq "Collection")
    {
        $select = "
        select fcm.CollectionID, 
        sw.IsEnabled as 'Maint_Enabled',
        Col.Name As 'Collection_Name',    
        sw.Name AS 'MaintWindow_Name',
        SW.Description AS 'MaintWindowDesc',
        SW.StartTime AS 'MaintStartTime',
        sw.Duration as 'MaintDuration',
        sw.RecurrenceType as 'MaintRecurrance',    
        sw.ServiceWindowType as 'MaintWind_Type'
        from v_FullCollectionMembership fcm
        JOIN v_R_System vrs on fcm.ResourceID = vrs.ResourceID 
        JOIN v_Collection col on fcm.CollectionID = col.CollectionID 
        left JOIN v_ServiceWindow sw on fcm.CollectionID = sw.CollectionID
        Where vrs.Name0='$compname'
        ORDER BY Col.Name
        "
    }
    if($query -eq "Software")
    {
        $select = "
        select
        ProductName0,
        ProductVersion0,
        Publisher0,
        InstallDate0,
        VersionMajor0,
        VersionMinor0,
        InstalledLocation0,
        InstallSource0,
        PackageCode0,
        UninstallString0
        from
        v_R_System vrs
        join v_GS_INSTALLED_SOFTWARE sof on vrs.ResourceID = sof.ResourceID
        where
        vrs.Name0 = '$compname'
        Order by ProductName0
        " 
    }
    $sql = Invoke-Sqlcmd -Query $select -ServerInstance $SQLInstance -Database $SQLDatabase
    return $sql
}
# Add the elements to the form
$GetInfoForm.controls.AddRange(@($NomadLog,$CompName,$ModelBox,$OSBox,$TPMBox,$ProtBox,$EncBox,$gpupdate,$rmbutton,$rdp,$PingDashTButton,$CLIinstall,$clibutton,$reboot,$ScanAppButton,$MachinePolicy,$HardwareInventoryScan,$MachinePolicyEval,$SCCMsoftwareButton,$PSSessionButton,$IPbox,$CCMRestartButton,$CCMRepairButton,$ccmevalbutton,$RSATbutton,$SQLButton,$LocalLabel,$Title,$Description,$outputBox,$InstallClient,$PingButton,$SoftwareCheckButton,$ForceInstallClient,$PCButton,$ADButton,$SCCMButton,$LogButton,$SCCMCheckButton))
# Display the form
[void]$GetInfoForm.ShowDialog()
Remove-Item $tempfile.FullName