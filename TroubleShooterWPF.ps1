#Requires -Version 7
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
        Copy-Item -Path '\\itsys-sccm\SMS_PS2\Client\*' -Destination "\\$comp\c$\Windows\Temp" -Force -Recurse ########################## CHANGE
        Invoke-Command -computername $comp -ScriptBlock {Start-Process -FilePath "c:\Windows\Temp\ccmsetup.exe" -ArgumentList "/forceinstall","SMSSITECODE=PS2","FSP=itsys-sccm","CCMENABLELOGGING=TRUE","CCMLOGLEVEL=0"} ########################## CHANGE
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
    'Modified'
    'OperatingSystem'
    'OperatingSystemVersion'
    'PasswordLastSet'
    )
    $adres = get-adcomputer -Identity $compName -Properties $properties
    $res.Text += "`n---------- AD Info ----------`n"
    $res.Text += $adres | Select-Object Name,@{Name="LastLogonTimeStamp";expression={([datetime]::FromFileTime($_.LastLogonTimeStamp))}},Description,Created,Modified,Deleted,Enabled,OperatingSystem,OperatingSystemVersion,PasswordLastSet,IPv4address,CanonicalName | Format-List | Out-String
    $res.ScrollToEnd()
}
function get-adgroup {
    param (
        [Parameter(Mandatory)]
        [string]$CompName
    )
    $adres = get-adcomputer -Identity $compName -Properties MemberOf
    $res.Text += "`n---------- Group Membership ----------`n"
    $res.Text += $adres.Name + "`n"
    $res.Text += $adres.MemberOf | Format-List | Out-String
    $res.ScrollToEnd()
}
function Get-SCCMdata {
    param (
        [Parameter(Mandatory)]
        [string]$CompName,
        [string]$query 
    )
    $SQLInstance = "itsys-sccm"
    $SQLDatabase = "CM_PS2"
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
            left join v_GS_WORKSTATION_STATUS stat on vrs.ResourceID = stat.ResourceID
            left join v_GS_PC_BIOS bios on bios.ResourceID = vrs.ResourceID
            left join v_GS_COMPUTER_SYSTEM comp on vrs.ResourceID = comp.ResourceID
            left join v_GS_OPERATING_SYSTEM OS on vrs.ResourceID = os.ResourceID
            left join v_GS_TPM TPM on vrs.ResourceID = tpm.ResourceID
            left join v_GS_PROCESSOR CPU on vrs.ResourceID = cpu.ResourceID
            left join v_GS_LOGICAL_DISK disc on vrs.ResourceID = disc.ResourceID
            left join PC_Memory_DATA mem on vrs.ResourceID = mem.MachineID
            where 
            disc.DeviceID0 = 'C:' AND
            vrs.Name0 = '$compname'
            "
    }
    if ($query -eq "Collections")
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
        ProductVersion0
        from
        v_R_System vrs
        join v_GS_INSTALLED_SOFTWARE sof on vrs.ResourceID = sof.ResourceID
        where
        vrs.Name0 = '$compname'
        Order by ProductName0
        " 
    }
    $sql = Invoke-Sqlcmd -Query $select -ServerInstance $SQLInstance -Database $SQLDatabase
    $res.Text += "`n---------- Config Mgr Database Info ----------`n"
    $res.Text += "`n---------- $query ----------`n"
    $res.text += $CompName + "`n"
    if($query -eq 'Collections'){
        $res.Text += $sql | Format-Table | Out-String
        $res.Text += "`n---------- Maintenance Windows ----------`n"
        $res.Text += $sql | Where-Object Maint_Enabled -EQ $true | Select-Object CollectionID,MaintWindow_Name,MaintWindowDesc,MaintStartTime,MaintDuration,MaintRecurrance,Maint_Enabled,MaintWind_Type | Format-List | Out-String
    }else{
        $res.Text += $sql | Out-String
    }
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
                <Button Name="GetADGroup" Grid.Column="3" Grid.Row="4" ToolTip="AD Group Membership" Content="AD Groups" HorizontalAlignment="Center" Height="26" Width="100" Margin="5" VerticalAlignment="Center" Background="DarkGray" />
                <Label Name="ConfigMgrInfo" Grid.Column="4" Grid.Row="2" Content="ConfigMgr DB" Height="26" HorizontalAlignment="Center" VerticalAlignment="Center" Foreground="DarkGray"/>
                <Button Name="GetConfigInfo" Grid.Column="4" Grid.Row="3" ToolTip="ConfigMgr info" Content="ConfigMgr Info" HorizontalAlignment="Center" Height="26" Width="100" Margin="5" VerticalAlignment="Center" Background="DarkGray" />
                <Button Name="GetConfigColl" Grid.Column="4" Grid.Row="4" ToolTip="ConfigMgr Collections and Maintenance Windows" Content="Collections-Maint" HorizontalAlignment="Center" Height="26" Width="100" Margin="5" VerticalAlignment="Center" Background="DarkGray" />
                <Button Name="GetConfigSoft" Grid.Column="4" Grid.Row="5" ToolTip="ConfigMgr Installed Software" Content="Installed Software" HorizontalAlignment="Center" Height="26" Width="100" Margin="5" VerticalAlignment="Center" Background="DarkGray" />
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
$adgrp = $win.FindName("GetADGroup")
$configinfo = $win.FindName("GetConfigInfo")
$configcoll = $win.FindName("GetConfigColl")
$configsoft = $win.FindName("GetConfigSoft")

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
$adgrp.Add_Click({
    $computer = $comp.text
    if($computer -eq ''){
        [System.Windows.MessageBox]::Show("Please enter a computer name", "Missing Value")
    }else{
        try {
            Get-ADGroup $computer
        }
        catch {
            [System.Windows.MessageBox]::Show($error[0].Exception.Message,"Error")
        }
    }

})
$configinfo.Add_Click({
    $computer = $comp.text
    if($computer -eq ''){
        [System.Windows.MessageBox]::Show("Please enter a computer name", "Missing Value")
    }else{
        try {
            Get-SCCMdata $computer 'Hardware'
        }
        catch {
            [System.Windows.MessageBox]::Show($error[0].Exception.Message,"Error")
        }
    }

})
$configcoll.Add_Click({
    $computer = $comp.text
    if($computer -eq ''){
        [System.Windows.MessageBox]::Show("Please enter a computer name", "Missing Value")
    }else{
        try {
            Get-SCCMdata $computer 'Collections'
        }
        catch {
            [System.Windows.MessageBox]::Show($error[0].Exception.Message,"Error")
        }
    }

})
$configsoft.Add_Click({
    $computer = $comp.text
    if($computer -eq ''){
        [System.Windows.MessageBox]::Show("Please enter a computer name", "Missing Value")
    }else{
        try {
            Get-SCCMdata $computer 'Software'
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
        $res.Text += "This script was designed to run with Powershell 7 but you seem to be using an earlier version not supported by this script. Some things may work, but most will probably not.`n"
    }
})
$Win.Showdialog()
# SIG # Begin signature block
# MIIT/wYJKoZIhvcNAQcCoIIT8DCCE+wCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUyTIf9vy/2/62KL7zsoVIQzdF
# 6IOgghE3MIIFgTCCBGmgAwIBAgIQOXJEOvkit1HX02wQ3TE1lTANBgkqhkiG9w0B
# AQwFADB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVy
# MRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEh
# MB8GA1UEAwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTE5MDMxMjAwMDAw
# MFoXDTI4MTIzMTIzNTk1OVowgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcg
# SmVyc2V5MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJU
# UlVTVCBOZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgUlNBIENlcnRpZmljYXRp
# b24gQXV0aG9yaXR5MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAgBJl
# FzYOw9sIs9CsVw127c0n00ytUINh4qogTQktZAnczomfzD2p7PbPwdzx07HWezco
# EStH2jnGvDoZtF+mvX2do2NCtnbyqTsrkfjib9DsFiCQCT7i6HTJGLSR1GJk23+j
# BvGIGGqQIjy8/hPwhxR79uQfjtTkUcYRZ0YIUcuGFFQ/vDP+fmyc/xadGL1RjjWm
# p2bIcmfbIWax1Jt4A8BQOujM8Ny8nkz+rwWWNR9XWrf/zvk9tyy29lTdyOcSOk2u
# TIq3XJq0tyA9yn8iNK5+O2hmAUTnAU5GU5szYPeUvlM3kHND8zLDU+/bqv50TmnH
# a4xgk97Exwzf4TKuzJM7UXiVZ4vuPVb+DNBpDxsP8yUmazNt925H+nND5X4OpWax
# KXwyhGNVicQNwZNUMBkTrNN9N6frXTpsNVzbQdcS2qlJC9/YgIoJk2KOtWbPJYjN
# hLixP6Q5D9kCnusSTJV882sFqV4Wg8y4Z+LoE53MW4LTTLPtW//e5XOsIzstAL81
# VXQJSdhJWBp/kjbmUZIO8yZ9HE0XvMnsQybQv0FfQKlERPSZ51eHnlAfV1SoPv10
# Yy+xUGUJ5lhCLkMaTLTwJUdZ+gQek9QmRkpQgbLevni3/GcV4clXhB4PY9bpYrrW
# X1Uu6lzGKAgEJTm4Diup8kyXHAc/DVL17e8vgg8CAwEAAaOB8jCB7zAfBgNVHSME
# GDAWgBSgEQojPpbxB+zirynvgqV/0DCktDAdBgNVHQ4EFgQUU3m/WqorSs9UgOHY
# m8Cd8rIDZsswDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wEQYDVR0g
# BAowCDAGBgRVHSAAMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2Rv
# Y2EuY29tL0FBQUNlcnRpZmljYXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgw
# JjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3
# DQEBDAUAA4IBAQAYh1HcdCE9nIrgJ7cz0C7M7PDmy14R3iJvm3WOnnL+5Nb+qh+c
# li3vA0p+rvSNb3I8QzvAP+u431yqqcau8vzY7qN7Q/aGNnwU4M309z/+3ri0ivCR
# lv79Q2R+/czSAaF9ffgZGclCKxO/WIu6pKJmBHaIkU4MiRTOok3JMrO66BQavHHx
# W/BBC5gACiIDEOUMsfnNkjcZ7Tvx5Dq2+UUTJnWvu6rvP3t3O9LEApE9GQDTF1w5
# 2z97GA1FzZOFli9d31kWTz9RvdVFGD/tSo7oBmF0Ixa1DVBzJ0RHfxBdiSprhTEU
# xOipakyAvGp4z7h/jnZymQyd/teRCBaho1+VMIIFvzCCBKegAwIBAgIQa0z8Ghqz
# 4mCqfZWWmfVfWTANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzELMAkGA1UE
# CBMCTUkxEjAQBgNVBAcTCUFubiBBcmJvcjESMBAGA1UEChMJSW50ZXJuZXQyMREw
# DwYDVQQLEwhJbkNvbW1vbjElMCMGA1UEAxMcSW5Db21tb24gUlNBIENvZGUgU2ln
# bmluZyBDQTAeFw0yMDA3MjgwMDAwMDBaFw0yMzA3MjgyMzU5NTlaMIHSMQswCQYD
# VQQGEwJVUzEOMAwGA1UEEQwFNjI5MDExETAPBgNVBAgMCElsbGlub2lzMRMwEQYD
# VQQHDApDYXJib25kYWxlMRcwFQYDVQQJDA42MjUgV2hhbSBEcml2ZTElMCMGA1UE
# CgwcU291dGhlcm4gSWxsaW5vaXMgVW5pdmVyc2l0eTEkMCIGA1UECwwbU0lVQyBJ
# bmZvcm1hdGlvbiBUZWNobm9sb2d5MSUwIwYDVQQDDBxTb3V0aGVybiBJbGxpbm9p
# cyBVbml2ZXJzaXR5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4pvj
# THO7wprzC0rPonW5WcOJh/TxpWriTErglx4D+priqfmryn3XNfDP7PU1Mbzc3o4w
# jTq/Um+yQNa0KBIsstbrcyzxI/5m60sNg9Kqz3fDmfrjuWryOKNxq+l9QPjNzWIP
# Wnx2JQqDk0LjXOYcQ6dyJxBezH6Bo5O2QqD8BFJPZsuLjMomV1PZMZpvHyR47Bm/
# DeiYOXHVco/8dxAVFyOsOxyQT1F3zcC+swu8DjNr2VDdvDVKCbAyzJHdSt/HKBSH
# YHkFc976kJGChGUXrHwY4x+49p0YDIllljgoIQC5ZkyFvJj9fHB48R9/ROAVGu4z
# lBltYpENOleWTAjcbQIDAQABo4IB5DCCAeAwHwYDVR0jBBgwFoAUrjUjF///Bj2c
# UOCMJGUzHnAQiKIwHQYDVR0OBBYEFEFr/TDI9iLUXAMAoiMnXoLEwVECMA4GA1Ud
# DwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMBEG
# CWCGSAGG+EIBAQQEAwIEEDBwBgNVHSAEaTBnMFsGDCsGAQQBriMBBAMCATBLMEkG
# CCsGAQUFBwIBFj1odHRwczovL3d3dy5pbmNvbW1vbi5vcmcvY2VydC9yZXBvc2l0
# b3J5L2Nwc19jb2RlX3NpZ25pbmcucGRmMAgGBmeBDAEEATBJBgNVHR8EQjBAMD6g
# PKA6hjhodHRwOi8vY3JsLmluY29tbW9uLXJzYS5vcmcvSW5Db21tb25SU0FDb2Rl
# U2lnbmluZ0NBLmNybDB+BggrBgEFBQcBAQRyMHAwRAYIKwYBBQUHMAKGOGh0dHA6
# Ly9jcnQuaW5jb21tb24tcnNhLm9yZy9JbkNvbW1vblJTQUNvZGVTaWduaW5nQ0Eu
# Y3J0MCgGCCsGAQUFBzABhhxodHRwOi8vb2NzcC5pbmNvbW1vbi1yc2Eub3JnMBsG
# A1UdEQQUMBKBEGRtY25lbGx5QHNpdS5lZHUwDQYJKoZIhvcNAQELBQADggEBAIrg
# r+D+QHqbKXXC2UkDB8jRJjeOsn/v2fG4FV/S8PnKh4JavbLLbXNo+b3ulB/VXJCM
# lsmyYUA/OnWlKjX6Z1EKwdkVl/JHmOjVgmD+pPREtYG2kG/7Ge81s8yD86Vb3ufO
# W1C3klQA1eTYNXHEQwcva17a229fHBRy6Y7iKqBx8ZIXp0I4+gd/sr+gRvHp6A5/
# qlxFIGI/KqzBmMUZeby7ggphGo+HvQ7/AZPK86m5s3+LUIIYYcqFjq3K26ydY1z9
# 9ErlmnllcCLnEbzZTkACEIbujOosxaQzp6BhGWvMx6LXO/1a6BwoLA52YTFka5cY
# M0WEdoGYG9gU+JbeKqMwggXrMIID06ADAgECAhBl4eLj1d5QRYXzJiSABeLUMA0G
# CSqGSIb3DQEBDQUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKTmV3IEplcnNl
# eTEUMBIGA1UEBxMLSmVyc2V5IENpdHkxHjAcBgNVBAoTFVRoZSBVU0VSVFJVU1Qg
# TmV0d29yazEuMCwGA1UEAxMlVVNFUlRydXN0IFJTQSBDZXJ0aWZpY2F0aW9uIEF1
# dGhvcml0eTAeFw0xNDA5MTkwMDAwMDBaFw0yNDA5MTgyMzU5NTlaMHwxCzAJBgNV
# BAYTAlVTMQswCQYDVQQIEwJNSTESMBAGA1UEBxMJQW5uIEFyYm9yMRIwEAYDVQQK
# EwlJbnRlcm5ldDIxETAPBgNVBAsTCEluQ29tbW9uMSUwIwYDVQQDExxJbkNvbW1v
# biBSU0EgQ29kZSBTaWduaW5nIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
# CgKCAQEAwKAvix56u2p1rPg+3KO6OSLK86N25L99MCfmutOYMlYjXAaGlw2A6O2i
# gTXrC/Zefqk+aHP9ndRnec6q6mi3GdscdjpZh11emcehsriphHMMzKuHRhxqx+85
# Jb6n3dosNXA2HSIuIDvd4xwOPzSf5X3+VYBbBnyCV4RV8zj78gw2qblessWBRyN9
# EoGgwAEoPgP5OJejrQLyAmj91QGr9dVRTVDTFyJG5XMY4DrkN3dRyJ59UopPgNwm
# ucBMyvxR+hAJEXpXKnPE4CEqbMJUvRw+g/hbqSzx+tt4z9mJmm2j/w2nP35MViPW
# Cb7hpR2LB8W/499Yqu+kr4LLBfgKCQIDAQABo4IBWjCCAVYwHwYDVR0jBBgwFoAU
# U3m/WqorSs9UgOHYm8Cd8rIDZsswHQYDVR0OBBYEFK41Ixf//wY9nFDgjCRlMx5w
# EIiiMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMBMGA1UdJQQM
# MAoGCCsGAQUFBwMDMBEGA1UdIAQKMAgwBgYEVR0gADBQBgNVHR8ESTBHMEWgQ6BB
# hj9odHRwOi8vY3JsLnVzZXJ0cnVzdC5jb20vVVNFUlRydXN0UlNBQ2VydGlmaWNh
# dGlvbkF1dGhvcml0eS5jcmwwdgYIKwYBBQUHAQEEajBoMD8GCCsGAQUFBzAChjNo
# dHRwOi8vY3J0LnVzZXJ0cnVzdC5jb20vVVNFUlRydXN0UlNBQWRkVHJ1c3RDQS5j
# cnQwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0cnVzdC5jb20wDQYJKoZI
# hvcNAQENBQADggIBAEYstn9qTiVmvZxqpqrQnr0Prk41/PA4J8HHnQTJgjTbhuET
# 98GWjTBEE9I17Xn3V1yTphJXbat5l8EmZN/JXMvDNqJtkyOh26owAmvquMCF1pKi
# QWyuDDllxR9MECp6xF4wnH1Mcs4WeLOrQPy+C5kWE5gg/7K6c9G1VNwLkl/po9OR
# PljxKKeFhPg9+Ti3JzHIxW7LdyljffccWiuNFR51/BJHAZIqUDw3LsrdYWzgg4x0
# 6tgMvOEf0nITelpFTxqVvMtJhnOfZbpdXZQ5o1TspxfTEVOQAsp05HUNCXyhznlV
# Lr0JaNkM7edgk59zmdTbSGdMq8Ztuu6VyrivOlMSPWmay5MjvwTzuNorbwBv0DL+
# 7cyZBp7NYZou+DoGd1lFZN0jU5IsQKgm3+00pnnJ67crdFwfz/8bq3MhTiKOWEb0
# 4FT3OZVp+jzvaChHWLQ8gbCORgClaZq1H3aqI7JeRkWEEEp6Tv4WAVsr/i7LoXU7
# 2gOb8CAzPFqwI4Excdrxp0I4OXbECHlDqU4sTInqwlMwofmxeO4u94196qIqJQl+
# 8Sykl06VktqMux84Iw3ZQLH08J8LaJ+WDUycc4OjY61I7FGxCDkbSQf3npXeRFm0
# IBn8GiW+TRDk6J2XJFLWEtVZmhboFlBLoUlqHUCKu0QOhU/+AEOqnY98j2zRMYIC
# MjCCAi4CAQEwgZAwfDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAk1JMRIwEAYDVQQH
# EwlBbm4gQXJib3IxEjAQBgNVBAoTCUludGVybmV0MjERMA8GA1UECxMISW5Db21t
# b24xJTAjBgNVBAMTHEluQ29tbW9uIFJTQSBDb2RlIFNpZ25pbmcgQ0ECEGtM/Boa
# s+Jgqn2Vlpn1X1kwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAIoAKAAKEC
# gAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwG
# CisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFNiUsJrChyrpPGtXY750RQ3VkgzH
# MA0GCSqGSIb3DQEBAQUABIIBANAPz6NtGL6I14vUG8ONQasZ0+aJ7cq9LBFyB4RG
# xocMjfcp0y67hhe65l7R0JZaV8qrWdTKujyqun8/RCo8HKFFPHPek3caVrH+iZqB
# FPRbXd9GGHvFCUkuzYUp2bc56AMbuzaOu5fvJ9SauSYLPry75h8cS7f1XlYx7rwx
# helw6wSEQN/HSV4N2OGND6tiAaUDjj9r7Ka11PBCiYJ/pX0iIeGC6l7qsx6BpsIx
# BWZp848HK4LNfbhe8vQeKOpOEIbpsqiW4KPeiIhvJUV84hCVc9SdtZlcdxz4ZpRC
# d7f2XhnIt7Yx0LF3YHyFFKM2UC1WspXUZOOlFNFllHwgBD4=
# SIG # End signature block
