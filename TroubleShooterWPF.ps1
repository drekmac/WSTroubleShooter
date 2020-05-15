#Created for Powershell 7
Add-Type -AssemblyName PresentationFramework

#Functions
Function Get-Ping($comp){  
    $res.Text += Test-Connection -TargetName $comp | Out-String
    $res.ScrollToEnd()
}
Function Get-Basic($comp){
    try{
        $session = New-CimSession -ComputerName $Comp -ErrorAction Stop
        $ip = Get-NetIPAddress -AddressFamily ipv4 -CimSession $session -ErrorAction ignore | where-object {$_.AddressState -eq 'Preferred' -and $_.IpAddress -ne '127.0.0.1'}
        $CompSystem = Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $session
        $Bios = Get-CimInstance -ClassName Win32_Bios -CimSession $session
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $session
        $Disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -CimSession $session
        [string]$Uptime = ((get-date) - $OS.LastBootUpTime).TotalHours
        $HDD = "{0:N2}" -f ($Disk.Size/1GB) + " GB"
        $freedisk = "{0:N2}" -f ($disk.FreeSpace/1GB) + " GB"
        $RAM = "{0:N2}" -f ($CompSystem.TotalPhysicalMemory/1GB) + "GB"
        $ps = New-Object PSObject -Property @{
            "Name" = $Comp
            "IP" = $ip
            "BIOS" = $Bios.SMBIOSBIOSVersion
            "Model" = $CompSystem.Model
            "OS" = $OS.Caption
            "OS_Ver" = $OS.Version
            "Uptime" = $uptime + " hours"
            "C:_Total" = $HDD
            "C:_Free" = $freedisk
            "RAM" = $RAM
        }
        $res.text += "`n---------- Basic Info ----------`n"
        $res.text += $ps | Select-Object Name,IP,Model,OS,OS_Ver,BIOS,Uptime,C:_Total,C:_Free,RAM | Out-String
        $res.ScrollToEnd()
    }catch{
        [System.Windows.MessageBox]::Show($error[0].Exception.Message,"Error")
    }
    if($session){
        Remove-CimSession $session
    }
}
Function Get-TPMinfo($comp){    
    try{
        $session = New-CimSession -ComputerName $Comp -ErrorAction Stop
        $Bios = Get-CimInstance -ClassName Win32_Bios -CimSession $session
        $tpminfo = Get-CimInstance -ClassName win32_tpm -Namespace root\cimv2\security\microsofttpm -CimSession $session
        $ps = New-Object PSObject -Property @{
            "Name" = $comp
            "FullVer" = $tpminfo.ManufacturerVersionFull20
            "Ver" = $tpminfo.ManufacturerVersion
            "Spec" = $tpminfo.SpecVersion
            "Enabled" = $tpminfo.IsEnabled_InitialValue
            "Activated" = $tpminfo.IsActivated_InitialValue
            "Owned" = $tpminfo.IsOwned_InitialValue
            "Bios" = $Bios.SMBIOSBIOSVersion
        }
        $res.text += "`n---------- TPM Info ----------`n"
        $res.text += $ps | Select-Object Name,FullVer,Ver,Spec,Enabled,Activated,Owned,Bios | Out-String
        $res.ScrollToEnd()
    }catch{
        [System.Windows.MessageBox]::Show($error[0].Exception.Message,"Error")
    }   
    if($session){
        Remove-CimSession $session
    } 
}
Function Get-CompSoftInfo($comp){    
    try{
        $session = New-CimSession -ComputerName $Comp -ErrorAction Stop
        $softInfo = Get-CimInstance Win32Reg_AddRemovePrograms -CimSession $session | Select-Object DisplayName,Version | Sort-Object DisplayName | Format-Table -AutoSize | Out-String
        $res.text += "`n---------- Software Installs ----------`n"
        $res.text += $comp + "`n" + $softInfo
        $res.ScrollToEnd()
    }catch{
        [System.Windows.MessageBox]::Show($error[0].Exception.Message,"Error")
    }   
    if($session){
        Remove-CimSession $session
    } 
}
Function Install-Client($comp){
    try{
        Remove-Item "\\$comp\c$\Windows\Temp\CCMsetup.exe" -Force -ErrorAction Ignore
        Copy-Item -Path '\\wdc-vsdsps1p01\SMS_PS1\Client\ccmsetup.exe' -Destination "\\$comp\c$\Windows\Temp" -Force ########################## CHANGE
        Invoke-Command -computername $comp -ScriptBlock {Start-Process -FilePath "c:\Windows\Temp\ccmsetup.exe" -ArgumentList "/forceinstall","SMSSITECODE=PS1","FSP=WDC-VSDFSPR1P01","CCMENABLELOGGING=TRUE","CCMLOGLEVEL=0"} ########################## CHANGE
        CMTrace.exe "\\$comp\c$\Windows\ccmsetup\logs\ccmsetup.log"
    }catch{
        [System.Windows.MessageBox]::Show($error[0].Exception.Message,"Error")
    }
}
Function Start-PolicyEval($comp){
    try{
        $sessionoption = New-CimSessionOption -Protocol DCOM
        $session = New-CimSession -ComputerName $Comp -SessionOption $sessionoption -ErrorAction Stop
        $req = Invoke-CIMMethod -CimSession $session -Namespace root\ccm -ClassName SMS_CLIENT -MethodName TriggerSchedule -Arguments @{sScheduleID = '{00000000-0000-0000-0000-000000000021}'}
        if($req){$res.Text += "`nPolicy request initiated";$res.ScrollToEnd()}else{$res.text += "`nPolicy request failed";$res.ScrollToEnd()}
        $eval = Invoke-CIMMethod -CimSession $session -Namespace root\ccm -ClassName SMS_CLIENT -MethodName TriggerSchedule -Arguments @{sScheduleID = '{00000000-0000-0000-0000-000000000022}'}
        if($eval){$res.Text += "`nPolicy evaluation initiated";$res.ScrollToEnd()}else{$res.text += "`nPolicy evaluation failed";$res.ScrollToEnd()}
        $app = Invoke-CIMMethod -CimSession $session -Namespace root\ccm -ClassName SMS_CLIENT -MethodName TriggerSchedule -Arguments @{sScheduleID = '{00000000-0000-0000-0000-000000000121}'}
        if($app){$res.Text += "`nApplication evaluation initiated";$res.ScrollToEnd()}else{$res.text += "`nApplication evaluation failed";$res.ScrollToEnd()}
        $scan = Invoke-CIMMethod -CimSession $session -Namespace root\ccm -ClassName SMS_CLIENT -MethodName TriggerSchedule -Arguments @{sScheduleID = '{00000000-0000-0000-0000-000000000113}'}
        if($scan){$res.Text += "`nUpdate scan initiated";$res.ScrollToEnd()}else{$res.text += "`nUpdate scan failed";$res.ScrollToEnd()}
        $upeval = Invoke-CIMMethod -CimSession $session -Namespace root\ccm -ClassName SMS_CLIENT -MethodName TriggerSchedule -Arguments @{sScheduleID = '{00000000-0000-0000-0000-000000000108}'}
        if($upeval){$res.Text += "`nUpdate evaluation initiated";$res.ScrollToEnd()}else{$res.text += "`nUpdate evaluation failed";$res.ScrollToEnd()}
        $hw = Invoke-CIMMethod -CimSession $session -Namespace root\ccm -ClassName SMS_CLIENT -MethodName TriggerSchedule -Arguments @{sScheduleID = '{00000000-0000-0000-0000-000000000001}'}
        if($hw){$res.Text += "`nHardware scan initiated`n";$res.ScrollToEnd()}else{$res.text += "`nHardware scan failed`n";$res.ScrollToEnd()}
    }catch{
        [System.Windows.MessageBox]::Show($error[0].Exception.Message,"Error")
    }
    if($session){
        Remove-CimSession $session
    } 
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
    $adres = get-adcomputer -Identity $compName -Properties $properties
    $res.Text += "`n---------- AD Info ----------`n"
    $res.Text += $adres | Select-Object Name,@{Name="LastLogonTimeStamp";expression={([datetime]::FromFileTime($_.LastLogonTimeStamp))}},Description,Created,Modified,Deleted,Enabled,OperatingSystem,OperatingSystemVersion,PasswordLastSet,IPv4address,CanonicalName | Format-List | Out-String
    $res.Text += "`n---------- Group Membership ----------`n"
    $res.Text += $adres.MemberOf | Format-List | Out-String
    $res.ScrollToEnd()
}

#GUI
[xml]$Form = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Workstation TroubleShooter" Height="800" Width="1200" Background="#FF262626">
        <StackPanel>
            <Label Name="Title" Content="Workstation Troubleshooter" Margin="10,0,0,0" HorizontalAlignment="Left" VerticalAlignment="Center" Height="50" Foreground="DarkGray" FontSize="21" />
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="110" />
                    <ColumnDefinition Width="110" />
                    <ColumnDefinition Width="110" />
                    <ColumnDefinition Width="110" />
                </Grid.ColumnDefinitions>
                <Grid.RowDefinitions>
                    <RowDefinition Height="30" />
                    <RowDefinition Height="30" />
                    <RowDefinition Height="30" />
                    <RowDefinition Height="30" />
                    <RowDefinition Height="30" />
                    <RowDefinition Height="30" />
                    <RowDefinition Height="30" />
                </Grid.RowDefinitions>
                <Label Name="Computer" Content="Computer" HorizontalAlignment="Left" Height="26" VerticalAlignment="Center" Foreground="DarkGray"/>
                <TextBox Name="Comp" Grid.Column="1" HorizontalAlignment="Stretch" Width="100" Text="W3XTZFH2" VerticalAlignment="Center" Background="DarkGray" />
                <Button Name="TestCon" Grid.Column="2"  ToolTip="Ping the computer once" Content="Test Connection" HorizontalAlignment="Left" Height="26" Width="100" Margin="5" VerticalAlignment="Center" Background="DarkGray" />
                <Label Name="PClabel" Grid.Row="2" Content="From PC" Height="26" HorizontalAlignment="Center" VerticalAlignment="Center" Foreground="DarkGray"/>
                <Button Name="Basic" Grid.Row="3" ToolTip="Basic WMI calls" Content="Basic Info" HorizontalAlignment="Center" Height="26" Width="100" Margin="5" VerticalAlignment="Center" Background="DarkGray" />
                <Button Name="TPM" Grid.Row="4" ToolTip="TPM WMI calls" Content="TPM Info" HorizontalAlignment="Center" Height="26" Width="100" Margin="5" VerticalAlignment="Center" Background="DarkGray" />
                <Button Name="CompSoftware" ToolTip="Info from Win32Reg_AddRemovePrograms" Grid.Row="5" Content="Installed Software" HorizontalAlignment="Center" Height="26" Width="100" Margin="5" VerticalAlignment="Center" Background="DarkGray" />
                <Button Name="Logs" Grid.Row="6" ToolTip="Open C:\Windows\CCM\Logs folder on remote computer" Content="Log Folder" HorizontalAlignment="Center" Height="26" Width="100" Margin="5" VerticalAlignment="Center" Background="DarkGray" />
                <Label Name="PCConnect" Grid.Column="1" Grid.Row="2" Content="Connect to PC" Height="26" HorizontalAlignment="Center" VerticalAlignment="Center" Foreground="DarkGray"/>
                <Button Name="RDP" Grid.Column="1" Grid.Row="3" ToolTip="Remote Desktop Connection to computer" Content="RDP" HorizontalAlignment="Center" Height="26" Width="100" Margin="5" VerticalAlignment="Center" Background="DarkGray" />
                <Button Name="PSSession" Grid.Column="1" Grid.Row="4" ToolTip="Enter-PSSession to computer" Content="PSSession" HorizontalAlignment="Center" Height="26" Width="100" Margin="5" VerticalAlignment="Center" Background="DarkGray" />
                <Button Name="CliCen" Grid.Column="1" Grid.Row="5" ToolTip="Start Client Center and connect to computer" Content="Client Center" HorizontalAlignment="Center" Height="26" Width="100" Margin="5" VerticalAlignment="Center" Background="DarkGray" />
                <Button Name="PingT" Grid.Column="1" Grid.Row="6" ToolTip="Run Ping -T" Content="Ping -T" HorizontalAlignment="Center" Height="26" Width="100" Margin="5" VerticalAlignment="Center" Background="DarkGray" />
                <Label Name="ConfigClient" Grid.Column="2" Grid.Row="2" Content="ConfigMgr Client" Height="26" HorizontalAlignment="Center" VerticalAlignment="Center" Foreground="DarkGray"/>
                <Button Name="ClientCheck" Grid.Column="2" Grid.Row="3" ToolTip="ConfigMgr client info" Content="Client Check" HorizontalAlignment="Center" Height="26" Width="100" Margin="5" VerticalAlignment="Center" Background="DarkGray" />
                <Button Name="ClientInstall" Grid.Column="2" Grid.Row="4" ToolTip="Install ConfigMgr client from \\wdc-vsdsps1p01\SMS_PS1\Client" Content="Install Client" HorizontalAlignment="Center" Height="26" Width="100" Margin="5" VerticalAlignment="Center" Background="DarkGray" />
                <Button Name="PolicyEval" Grid.Column="2" Grid.Row="5" ToolTip="Evaluate machine policies, app deployments, updates, and hardware inventory scan" Content="Policy Eval" HorizontalAlignment="Center" Height="26" Width="100" Margin="5" VerticalAlignment="Center" Background="DarkGray" />
                <Label Name="ADInfo" Grid.Column="3" Grid.Row="2" Content="AD Info" Height="26" HorizontalAlignment="Center" VerticalAlignment="Center" Foreground="DarkGray"/>
                <Button Name="GetADInfo" Grid.Column="3" Grid.Row="3" ToolTip="AD info" Content="AD Info" HorizontalAlignment="Center" Height="26" Width="100" Margin="5" VerticalAlignment="Center" Background="DarkGray" />
            </Grid>
            <Label Name="Res" Content="Results" Margin="10" HorizontalAlignment="Left" Height="24" VerticalAlignment="Top" Width="69" Foreground="DarkGray" FontWeight="Bold"/>                                
            <TextBox Name="Results" Margin="10" VerticalScrollBarVisibility="Auto" HorizontalAlignment="Left" Height="400" TextWrapping="Wrap" VerticalAlignment="Top" Width="1000" Background="LightGray" />            
        </StackPanel>
</Window>
"@
$NR = (New-Object System.Xml.XMLNodeReader $Form)
$Win = [Windows.Markup.XamlReader]::Load( $NR )

#Button Stuff

$TestCon = $Win.FindName("TestCon")
$comp = $win.FindName("Comp")
$res = $win.FindName("Results")
$basic = $win.FindName("Basic")
$tpm = $win.FindName("TPM")
$compSoft = $win.FindName("CompSoftware")
$log = $win.FindName("Logs")
$rdp = $win.FindName("RDP")
$PSSession = $win.FindName("PSSession")
$CliCen = $win.FindName("CliCen")
$PingT = $win.FindName("PingT")
$ClientCheck = $win.FindName("ClientCheck")
$ClientInstall = $win.FindName("ClientInstall")
$PolicyEval = $win.FindName("PolicyEval")
$ad = $win.FindName("GetADInfo")

$TestCon.Add_Click({
    $computer = $comp.text
    if($computer -eq ''){
        [System.Windows.MessageBox]::Show("Please enter a computer name", "Missing Value")
    }else{
        Get-Ping $computer
    }

})
$basic.Add_Click({
    $computer = $comp.text
    if($computer -eq ''){
        [System.Windows.MessageBox]::Show("Please enter a computer name", "Missing Value")
    }else{
        Get-Basic $computer
    }

})
$tpm.Add_Click({
    $computer = $comp.text
    if($computer -eq ''){
        [System.Windows.MessageBox]::Show("Please enter a computer name", "Missing Value")
    }else{
        Get-TPMinfo $computer
    }

})
$compsoft.Add_Click({
    $computer = $comp.text
    if($computer -eq ''){
        [System.Windows.MessageBox]::Show("Please enter a computer name", "Missing Value")
    }else{
        Get-CompSoftInfo $computer
    }

})
$log.Add_Click({
    $computer = $comp.text
    if($computer -eq ''){
        [System.Windows.MessageBox]::Show("Please enter a computer name", "Missing Value")
    }else{
        Invoke-Item "\\$computer\c$\Windows\ccm\logs\"
    }

})
$rdp.Add_Click({
    $computer = $comp.text
    if($computer -eq ''){
        [System.Windows.MessageBox]::Show("Please enter a computer name", "Missing Value")
    }else{
        try{
            mstsc /v:$computer
        }catch{
            [System.Windows.MessageBox]::Show($error[0].Exception.Message,"Error")
        }
    }

})
$PSSession.Add_Click({
    $computer = $comp.text
    if($computer -eq ''){
        [System.Windows.MessageBox]::Show("Please enter a computer name", "Missing Value")
    }else{
        try{
            Start-Process -FilePath 'pwsh.exe' -ArgumentList '-NoExit',"-command `"Enter-PSSession -ComputerName $computer`""
        }catch{
            [System.Windows.MessageBox]::Show($error[0].Exception.Message,"Error")
        }
    }

})
$CliCen.Add_Click({
    $computer = $comp.text
    if($computer -eq ''){
        [System.Windows.MessageBox]::Show("Please enter a computer name", "Missing Value")
    }else{
        try{
            $ClientCenter = "C:\Program Files\Client Center for Configuration Manager\SCCMCliCtrWPF.exe"
            if(Test-Path $ClientCenter){
                & $ClientCenter $Computer
            }else{
                [System.Windows.MessageBox]::Show("Can't find Client Center, is it installed?","Error")
            }
        }
        catch{
            [System.Windows.MessageBox]::Show($error[0].Exception.Message,"Error")
        }
    }

})
$PingT.Add_Click({
    $computer = $comp.text
    if($computer -eq ''){
        [System.Windows.MessageBox]::Show("Please enter a computer name", "Missing Value")
    }else{
        try{
            Start-Process -FilePath 'pwsh.exe' -ArgumentList '-NoExit',"-command `"Ping -t $Computer`""
        }catch{
            [System.Windows.MessageBox]::Show($error[0].Exception.Message,"Error")
        }
    }

})
$ClientCheck.Add_Click({
    $computer = $comp.text
    if($computer -eq ''){
        [System.Windows.MessageBox]::Show("Please enter a computer name", "Missing Value")
    }else{
        try{
            $software = Get-CimInstance Win32Reg_AddRemovePrograms -ComputerName $Computer | Where-Object DisplayName -EQ "Configuration Manager Client"
            if($Software){
                $res.Text += $software | Out-String
                $res.ScrollToEnd()
            }
            else{
                [System.Windows.MessageBox]::Show("Can't find Configuration Manger Client in Add/Remove Programs","Error")
            }
        }catch{
            [System.Windows.MessageBox]::Show($error[0].Exception.Message,"Error")
        }
    }

})
$ClientInstall.Add_Click({
    $computer = $comp.text
    if($computer -eq ''){
        [System.Windows.MessageBox]::Show("Please enter a computer name", "Missing Value")
    }else{
        Install-Client $computer
    }

})
$PolicyEval.Add_Click({
    $computer = $comp.text
    if($computer -eq ''){
        [System.Windows.MessageBox]::Show("Please enter a computer name", "Missing Value")
    }else{
        try {
            Start-PolicyEval $computer
        }
        catch {
            [System.Windows.MessageBox]::Show($error[0].Exception.Message,"Error")
        }
    }

})
$AD.Add_Click({
    $computer = $comp.text
    if($computer -eq ''){
        [System.Windows.MessageBox]::Show("Please enter a computer name", "Missing Value")
    }else{
        try {
            Get-ADInfo $computer
        }
        catch {
            [System.Windows.MessageBox]::Show($error[0].Exception.Message,"Error")
        }
    }

})
$win.Add_ContentRendered({
    $psver = $PSVersionTable.PSVersion
    $res.Text = $psver | Out-String
    if($psver.Major -ge 7){
        $res.Text += "This script was designed to run with Powershell 7 and it seems that it is. Gold star for you.`n"
    }else{
        $res.Text += "This script was designed to run with Powershell 7 but you seem to be using an earlier version not supported by this script. Somethings may work, but most will probably not.`n"
    }
})
$Win.Showdialog()