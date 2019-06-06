
$Global:syncHash = [hashtable]::Synchronized(@{})
$Global:syncHash.Host = $host

<#
    TO DOOOOOO
#>
## ajout d'infos sur l'utilisateur (si connexion à l'AD en ADSI)
## GPResult => DONE -> SI ON APPUIE SUR RELOAD, tant que le runspace est 
## l'utilisateur est il admin ? => DONE
## test réseaux (voir avec fifix), test si on est en APIPA (range apipa: https://wiki.wireshark.org/APIPA)
##     ping passerelle, passerelle internet => DONE
##     Ping on Demand (champ) => DONE
##     tracert on demand (champ) => DONE
## site AD en fonction de l'ip

## info proxy -> a dégager, (a  terme appliance, avec un agent bluecoat (service ))
## voir si on peut interroger l'agent bluecoat (son statut, pour savoir si le gars est en interne ou en externe)

Register-EngineEvent -SourceIdentifier "GpResultEvent" -Action {
    $Global:synchash.GpoApplied = $null
    $Global:synchash.GpoRefused = $null
    $Global:synchash.InvokeGpResult.runspace.close()
    $Global:synchash.InvokeGpResult.runspace.Dispose()
    $Global:synchash.InvokeGpResult = $null
}

Register-EngineEvent -SourceIdentifier "TracertEvent" -Action {
    $Global:syncHash.InvokeTracert.runspace.close()
    $Global:syncHash.InvokeTracert.runspace.Dispose()
    $Global:syncHash.InvokeTracert = $null
}

Register-EngineEvent -SourceIdentifier "PingEvent" -Action {
    $Global:syncHash.InvokePing.runspace.close()
    $Global:syncHash.InvokePing.runspace.Dispose()
    $Global:syncHash.InvokePing = $null
}

$Main = {
function Get-NetworkCardInfo(){
    $a = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
    #$netshprority = $(Invoke-Expression "netsh interface ip show interfaces")
    
    ForEach ( $card in $a )
    {
        #If ($card.OperationalStatus -eq 'Up')
        If ( $card.GetPhysicalAddress().ToString() -ne '' )
        {

            $IpProperties = $card.GetIpProperties()
            $Ipv4Properties = $IpProperties.GetIpv4properties()

            $Properties = [Ordered] @{
                Name = $Card.name
                Type = $Card.NetworkInterfaceType
                Status = $Card.OperationalStatus
                Speed = ""+ $($Card.Speed/1000/1000/1000) + " GB/s"
                MacAddress = $Card.GetPhysicalAddress()
                Description = $Card.Description
                IsDHCPEnabled = $Ipv4Properties.IsDHCPEnabled
                IsApipa = $Ipv4Properties.IsAutomaticPrivateAddressingActive
                Mtu = $Ipv4Properties.Mtu
                DnsAddresses = $IpProperties.DnsAddresses.IPAddressToString -join ", "
                DhcpServerAddress = $IpProperties.DhcpServerAddresses.IpAddressToString -join ", "
                GatewayAddresses = $IpProperties.GatewayAddresses.Address.IpAddressToString
            }

            foreach( $x in $IpProperties.UnicastAddresses) {
                If ( $x.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork ) {
                    $Properties.Ip = $x.Address
                    $Properties.Mask = $x.IPv4Mask
                }
            }

            If ( $Properties.Type -like "Wireless*" -and $Properties.Status -eq "Up" )
            {
                Foreach ( $Line in $(Invoke-Expression "netsh wlan show interfaces") )
                {
                    switch -regex ($line) {
                        "^\s{1,}Profil\s{2,}.:\s" { $WifiNetwork= ($line -replace "^\s{1,}Profil\s{2,}.:\s","").Trim();}
                        "^\s{1,}Signal\s{2,}.:\s" { $WifiSignal = ($line -replace "^\s{1,}Signal\s{2,}.:\s","").Trim();}
                        "^\s{1,}SSID\s{2,}.:\s"   { $WifiSSID   = ($line -replace "^\s{1,}SSID\s{2,}.:\s","").Trim();}
                    }
                    If ( $WifiNetwork -and $WifiSignal -and $WifiSSID ) { break }
                }
                $Properties.WifiNetwork = $WifiNetwork
                $Properties.WifiSSID = $WifiSSID
                $Properties.WifiSignal = $WifiSignal
            }

            If ( $Properties.Status -eq 'Up' -and $Properties.IsDHCPEnabled -eq $True )
            {
                $netinfo = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -filter "description='$($Properties.Description)'" | Select-Object *
                $properties.DhcpLeaseObtainedDate = get-date $([System.Management.ManagementDateTimeconverter]::ToDateTime($netinfo.DHCPLeaseObtained)) -Format "dd/MM/yyyy hh:mm:ss"
                $properties.DhcpLeaseExpirationDate = get-date $([System.Management.ManagementDateTimeconverter]::ToDateTime($netinfo.DHCPLeaseExpires)) -Format "dd/MM/yyyy hh:mm:ss"
            }
            new-object -TypeName psobject -Property $properties
        }
    }
}
Function Get-PendingReboot{
    <# 
    .SYNOPSIS 
        Gets the pending reboot status on a local or remote computer. 
    
    .DESCRIPTION 
        This function will query the registry on a local or remote computer and determine if the 
        system is pending a reboot, from either Microsoft Patching or a Software Installation. 
        For Windows 2008+ the function will query the CBS registry key as another factor in determining 
        pending reboot state.  "PendingFileRenameOperations" and "Auto Update\RebootRequired" are observed 
        as being consistant across Windows Server 2003 & 2008. 
    
        CBServicing = Component Based Servicing (Windows 2008) 
        WindowsUpdate = Windows Update / Auto Update (Windows 2003 / 2008) 
        CCMClientSDK = SCCM 2012 Clients only (DetermineIfRebootPending method) otherwise $null value 
        PendFileRename = PendingFileRenameOperations (Windows 2003 / 2008) 
    
    .PARAMETER ComputerName 
        A single Computer or an array of computer names.  The default is localhost ($env:COMPUTERNAME). 
    
    .PARAMETER ErrorLog 
        A single path to send error data to a log file. 
    
    .EXAMPLE 
        PS C:\> Get-PendingReboot -ComputerName (Get-Content C:\ServerList.txt) | Format-Table -AutoSize 
    
        Computer CBServicing WindowsUpdate CCMClientSDK PendFileRename PendFileRenVal RebootPending 
        -------- ----------- ------------- ------------ -------------- -------------- ------------- 
        DC01     False   False           False      False 
        DC02     False   False           False      False 
        FS01     False   False           False      False 
    
        This example will capture the contents of C:\ServerList.txt and query the pending reboot 
        information from the systems contained in the file and display the output in a table. The 
        null values are by design, since these systems do not have the SCCM 2012 client installed, 
        nor was the PendingFileRenameOperations value populated. 
    
    .EXAMPLE 
        PS C:\> Get-PendingReboot 
    
        Computer     : WKS01 
        CBServicing  : False 
        WindowsUpdate      : True 
        CCMClient    : False 
        PendComputerRename : False 
        PendFileRename     : False 
        PendFileRenVal     :  
        RebootPending      : True 
    
        This example will query the local machine for pending reboot information. 
    
    .EXAMPLE 
        PS C:\> $Servers = Get-Content C:\Servers.txt 
        PS C:\> Get-PendingReboot -Computer $Servers | Export-Csv C:\PendingRebootReport.csv -NoTypeInformation 
    
        This example will create a report that contains pending reboot information. 
    
    .LINK 
        Component-Based Servicing: 
        http://technet.microsoft.com/en-us/library/cc756291(v=WS.10).aspx 
    
        PendingFileRename/Auto Update: 
        http://support.microsoft.com/kb/2723674 
        http://technet.microsoft.com/en-us/library/cc960241.aspx 
        http://blogs.msdn.com/b/hansr/archive/2006/02/17/patchreboot.aspx 
    
        SCCM 2012/CCM_ClientSDK: 
        http://msdn.microsoft.com/en-us/library/jj902723.aspx 
    
    .NOTES 
        Author:  Brian Wilhite 
        Email:   bcwilhite (at) live.com 
        Date:    29AUG2012 
        PSVer:   2.0/3.0/4.0/5.0 
        Updated: 01DEC2014 
        UpdNote: Added CCMClient property - Used with SCCM 2012 Clients only 
        Added ValueFromPipelineByPropertyName=$true to the ComputerName Parameter 
        Removed $Data variable from the PSObject - it is not needed 
        Bug with the way CCMClientSDK returned null value if it was false 
        Removed unneeded variables 
        Added PendFileRenVal - Contents of the PendingFileRenameOperations Reg Entry 
        Removed .Net Registry connection, replaced with WMI StdRegProv 
        Added ComputerPendingRename 
    #>	
    
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias("CN", "Computer")]
        [String[]]$ComputerName = "$env:COMPUTERNAME",
        
        [String]$ErrorLog
    )
    
    Begin { } ## End Begin Script Block 
    Process
    {
        Foreach ($Computer in $ComputerName)
        {
            Try
            {
                ## Setting pending values to false to cut down on the number of else statements 
                $CompPendRen, $PendFileRename, $Pending, $SCCM = $false, $false, $false, $false
                
                ## Setting CBSRebootPend to null since not all versions of Windows has this value 
                $CBSRebootPend = $null
                
                ## Querying WMI for build version 
                $WMI_OS = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber, CSName -ComputerName $Computer -ErrorAction Stop
                
                ## Making registry connection to the local/remote computer 
                $HKLM = [UInt32] "0x80000002"
                $WMI_Reg = [WMIClass] "\\$Computer\root\default:StdRegProv"
                
                ## If Vista/2008 & Above query the CBS Reg Key 
                If ([Int32]$WMI_OS.BuildNumber -ge 6001)
                {
                    $RegSubKeysCBS = $WMI_Reg.EnumKey($HKLM, "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")
                    $CBSRebootPend = $RegSubKeysCBS.sNames -contains "RebootPending"
                }
                
                ## Query WUAU from the registry 
                $RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM, "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
                $WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"
                
                ## Query PendingFileRenameOperations from the registry 
                $RegSubKeySM = $WMI_Reg.GetMultiStringValue($HKLM, "SYSTEM\CurrentControlSet\Control\Session Manager\", "PendingFileRenameOperations")
                $RegValuePFRO = $RegSubKeySM.sValue
                
                ## Query ComputerName and ActiveComputerName from the registry 
                $ActCompNm = $WMI_Reg.GetStringValue($HKLM, "SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\", "ComputerName")
                $CompNm = $WMI_Reg.GetStringValue($HKLM, "SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\", "ComputerName")
                If ($ActCompNm -ne $CompNm)
                {
                    $CompPendRen = $true
                }
                
                ## If PendingFileRenameOperations has a value set $RegValuePFRO variable to $true 
                If ($RegValuePFRO)
                {
                    $PendFileRename = $true
                }
                
                ## Determine SCCM 2012 Client Reboot Pending Status 
                ## To avoid nested 'if' statements and unneeded WMI calls to determine if the CCM_ClientUtilities class exist, setting EA = 0 
                $CCMClientSDK = $null
                $CCMSplat = @{
                    NameSpace = 'ROOT\ccm\ClientSDK'
                    Class ='CCM_ClientUtilities'
                    Name = 'DetermineIfRebootPending'
                    ComputerName = $Computer
                    ErrorAction = 'Stop'
                }
                ## Try CCMClientSDK 
                Try
                {
                    $CCMClientSDK = Invoke-WmiMethod @CCMSplat
                }
                Catch [System.UnauthorizedAccessException] {
                    $CcmStatus = Get-Service -Name CcmExec -ComputerName $Computer -ErrorAction SilentlyContinue
                    If ($CcmStatus.Status -ne 'Running')
                    {
                        Write-Warning "$Computer`: Error - CcmExec service is not running."
                        $CCMClientSDK = $null
                    }
                }
                Catch
                {
                    $CCMClientSDK = $null
                }
                
                If ($CCMClientSDK)
                {
                    If ($CCMClientSDK.ReturnValue -ne 0)
                    {
                        Write-Warning "Error: DetermineIfRebootPending returned error code $($CCMClientSDK.ReturnValue)"
                    }
                    If ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending)
                    {
                        $SCCM = $true
                    }
                }
                
                Else
                {
                    $SCCM = $null
                }
                
                ## Creating Custom PSObject and Select-Object Splat 
                $SelectSplat = @{
                    Property = (
                    'Computer',
                    'CBServicing',
                    'WindowsUpdate',
                    'CCMClientSDK',
                    'PendComputerRename',
                    'PendFileRename',
                    'PendFileRenVal',
                    'RebootPending'
                    )
                }
                New-Object -TypeName PSObject -Property @{
                    Computer = $WMI_OS.CSName
                    CBServicing = $CBSRebootPend
                    WindowsUpdate = $WUAURebootReq
                    CCMClientSDK = $SCCM
                    PendComputerRename = $CompPendRen
                    PendFileRename = $PendFileRename
                    PendFileRenVal = $RegValuePFRO
                    RebootPending = ($CompPendRen -or $CBSRebootPend -or $WUAURebootReq -or $SCCM -or $PendFileRename)
                } | Select-Object @SelectSplat
                
            }
            Catch
            {
                Write-Warning "$Computer`: $_"
                ## If $ErrorLog, log the file to a user specified location/path 
                If ($ErrorLog)
                {
                    Out-File -InputObject "$Computer`,$_" -FilePath $ErrorLog -Append
                }
            }
        } ## End Foreach ($Computer in $ComputerName)       
    } ## End Process 
    
    End { } ## End End 
    
}
#region xaml
Add-Type -AssemblyName PresentationCore,PresentationFramework,WindowsBase
#Pas supporté en V2 : xmlns:local="clr-namespace:"
[xml]$XAML  = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
    xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
    Title="Système info" SizeToContent="WidthAndHeight" ResizeMode="NoResize">
    <Grid>
        <Menu>
            <MenuItem x:Name="Menu_Reload" Header="_Reload"/>
            <MenuItem x:Name="Menu_Copy" Header="_CopyData"/>
        </Menu>
        <TabControl x:Name="MainTab" Margin="0,20,0,0">
            <TabItem Header="General">
                <Grid x:Name="grid0">
                    <StackPanel>
                        <GroupBox  x:Name="GrpBox_UserInfo" Header="User Info:"  HorizontalAlignment="Left" Margin="0,11,0,0"  VerticalAlignment="Top" Width="400">
                            <StackPanel x:Name="Stack_UserInfo" />
                        </GroupBox>
                        <GroupBox  x:Name="GrpBox_SysInfo" Header="Sys Info:"  HorizontalAlignment="Left" Margin="0,11,0,0"  VerticalAlignment="Top" Width="400">
                            <StackPanel x:Name="Stack_SysInfo" />
                        </GroupBox>
                        <GroupBox  x:Name="GrpBox_Reboot_Info" Header="Reboot Pending Info"  HorizontalAlignment="Left" Margin="0,11,0,0"  VerticalAlignment="Top" Width="400">
                            <StackPanel x:Name="Stack_Reboot_Info" />
                        </GroupBox>
                        <GroupBox  x:Name="GrpBox_DiskInfo" Header="Disk(s) Info:"  HorizontalAlignment="Left" Margin="0,11,0,0"  VerticalAlignment="Top" Width="400">
                            <StackPanel x:Name="Stack_DisksInfo" />
                        </GroupBox>
                    </StackPanel>
                </Grid>
            </TabItem>
            <TabItem x:Name="Tab_Reseau" Header="Network">
                <TabControl x:Name="TabNet" Margin="0,20,0,0"/>
            </TabItem>
            <TabItem x:Name="Tab_Test" Header="Test(s)">
                <Grid x:Name="grid2">
                    <StackPanel x:Name="Stack_NetTests">
                        <GroupBox  x:Name="GrpBox_NetInfo_Test" Header="Network Connectivity Tests"  HorizontalAlignment="Left" Margin="0,11,0,0"  VerticalAlignment="Top" Width="400">
                            <StackPanel x:Name="Stack_NetInfo_Test" />
                        </GroupBox>
                        <GroupBox  x:Name="GrpBox_NetInfo_Tracert" Header="On Demand Tracert Test(s)"  HorizontalAlignment="Left" Margin="0,11,0,0"  VerticalAlignment="Top" Width="400">
                            <Grid>
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="1*" />
                                    <RowDefinition Height="1*" />
                                </Grid.RowDefinitions>
                                <StackPanel Grid.Row="0" x:Name="Stack_NetInfo_Tracert" Orientation="Horizontal" >
                                    <Button x:Name="Button_Tracert" Content="Start Tracert" Width="100" Margin="0,11,10,0"/>
                                    <Button x:Name="Button_Stop_Tracert" Content="Stop Tracert" Width="100" Margin="0,11,10,0" />
                                    <Button x:Name="Button_Clear_Tracert" Content="Clear Tracert" Width="100" Margin="0,11,10,0" />
                                </StackPanel>
                                <StackPanel Grid.Row="1" HorizontalAlignment="Left">
                                    <TextBox x:Name="TextBox_Tracert" TextWrapping="Wrap" Text="Enter Ip/Dns Name and click Start Tracert..."  Margin="0,11,11,0" Width="300"/>
                                </StackPanel>
                            </Grid>
                        </GroupBox>
                        <GroupBox x:Name="GrpBox_Tracert_Result" Header="Tracert Result">
                            <ListView x:Name="ListView_Tracert" Height="100">
                                <ListView.View>
                                <GridView>
                                    <GridViewColumn Header="Hop N°" Width="50" DisplayMemberBinding="{Binding Hop}" />
                                    <GridViewColumn Header="First" Width="50" DisplayMemberBinding="{Binding First}"/>
                                    <GridViewColumn Header="Second" Width="50" DisplayMemberBinding="{Binding Second}"/>
                                    <GridViewColumn Header="Third" Width="50" DisplayMemberBinding="{Binding Third}"/>
                                    <GridViewColumn x:Name="GridNode" Header="Node" Width="Auto" DisplayMemberBinding="{Binding Node}"/>
                                </GridView>
                                </ListView.View>
                            </ListView>
                        </GroupBox>
                        <GroupBox  x:Name="GrpBox_NetInfo_Ping" Header="On Demand Ping Test(s)"  HorizontalAlignment="Left" Margin="0,11,0,0"  VerticalAlignment="Top" Width="400">
                            <Grid>
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="1*" />
                                    <RowDefinition Height="1*" />
                                </Grid.RowDefinitions>
                                <StackPanel Grid.Row="0" x:Name="Stack_NetInfo_Ping" Orientation="Horizontal" >
                                    <Button x:Name="Button_Ping" Content="Start Ping" Width="100" Margin="0,11,10,0"/>
                                    <Button x:Name="Button_Stop_Ping" Content="Stop Ping" Width="100" Margin="0,11,10,0" />
                                    <Button x:Name="Button_Clear_Ping" Content="Clear Ping" Width="100" Margin="0,11,10,0" />
                                </StackPanel>
                                <StackPanel Grid.Row="1" HorizontalAlignment="Left">
                                    <TextBox x:Name="TextBox_Ping" TextWrapping="Wrap" Text="Enter Ip/Dns Name and click Start Ping..."  Margin="0,11,11,0" Width="300"/>
                                </StackPanel>
                            </Grid>
                        </GroupBox>
                        <GroupBox x:Name="GrpBox_Ping_Result" Header="Ping Result">
                            <ListView x:Name="ListView_Ping" Height="100">
                                <ListView.View>
                                <GridView>
                                    <GridViewColumn Header="Destination°" Width="Auto" DisplayMemberBinding="{Binding Address}" />
                                    <GridViewColumn Header="Ipv4Address" Width="Auto" DisplayMemberBinding="{Binding IPV4Address}"/>
                                    <GridViewColumn Header="Bytes Sent" Width="50" DisplayMemberBinding="{Binding BufferSize}"/>
                                    <GridViewColumn Header="Bytes Rcvd" Width="50" DisplayMemberBinding="{Binding ReplySize}"/>
                                    <GridViewColumn Header="Time(ms)" Width="50" DisplayMemberBinding="{Binding ResponseTime}"/>
                                </GridView>
                                </ListView.View>
                            </ListView>
                        </GroupBox>
                    </StackPanel>
                    </Grid>
            </TabItem>
            <TabItem x:Name="Tab_Others" Header="Others">
                <Grid x:Name="grid5">
                    <StackPanel>
                    <GroupBox  x:Name="GrpBox_Proxy_Info" Header="Proxy Info"  HorizontalAlignment="Left" Margin="0,11,0,0"  VerticalAlignment="Top" Width="400">
                        <StackPanel x:Name="Stack_Proxy_Info" />
                    </GroupBox>
                    <GroupBox  x:Name="GrpBox_FireWall_Info" Header="Windows FireWall Info"  HorizontalAlignment="Left" Margin="0,11,0,0"  VerticalAlignment="Top" Width="400">
                        <StackPanel x:Name="Stack_FireWall_Info" />
                    </GroupBox>
                    <GroupBox  x:Name="GrpBox_GPO_Info" Header="Gpresult Return Info, working in background, please wait.."  HorizontalAlignment="Left" Margin="0,11,0,0"  VerticalAlignment="Top" Width="400">
                        <StackPanel x:Name="Stack_GPO_Info" />
                    </GroupBox>
                    </StackPanel>
                </Grid>
            </TabItem>
            <TabItem x:Name="Tab_Sccm" Header="Sccm Client">
                <Grid x:Name="grid3">
                    <GroupBox  x:Name="GrpBox_Sccm" Header="Sccm Client Info"  HorizontalAlignment="Left" Margin="0,11,0,0"  VerticalAlignment="Top" Width="400">
                        <StackPanel x:Name="Stack_Sccm_Info" />
                    </GroupBox>
                </Grid>
            </TabItem>
            <TabItem x:Name="Tab_Contact" Header="Contact">
                <Grid x:Name="grid4">
                    <GroupBox  x:Name="GrpBox_Contact" Header="Contact Info"  HorizontalAlignment="Left" Margin="0,11,0,0"  VerticalAlignment="Top" Width="400">
                        <StackPanel x:Name="Stack_Contact" />
                    </GroupBox>
                    </Grid>
            </TabItem>
        </TabControl>
    </Grid>
</Window>
"@


#endregion xaml

#region Fonctions_ajout_contenu
Function Add-Label($parent,$content,$Color,$width=370,$gradient)
{
    $NewChild = New-Object System.Windows.Controls.Label
    $NewChild.Content = $Content
    $NewChild.Width = $width
    If($Color)
    {
        $NewChild.Background = $color
    }

    If($Gradient)
    {
        $GradientBrush = New-object System.Windows.Media.LinearGradientBrush
        $GradientBrush.StartPoint = "0,0.5"
        $GradientBrush.EndPoint= "1,0.5"
        $Stop1 = New-Object Windows.Media.GradientStop("PaleGreen",$gradient)
        $Stop2 = New-Object Windows.Media.GradientStop("Crimson",$gradient)
        $GradientBrush.GradientStops.Add($Stop1)
        $GradientBrush.GradientStops.Add($Stop2)
        $NewChild.Background = $GradientBrush
    }
    try {
        Switch ($host.version)
        {
            "2.0"   {$parent.Children.add($NewChild)}
            "3.0"   {$parent.addChild($NewChild)}
            "4.0"   {$parent.addChild($NewChild)}
            default {$parent.addChild($NewChild)}
        }
    } catch {
    }

}

Function Add-TabItem($parent,$header)
{
    $NewChild = New-Object System.Windows.Controls.TabItem
    $NewChild.Header = $Header
    $Parent.addChild($NewChild)

    return $NewChild
}

Function Add-StackPanel($Parent)
{
    $NewChild = New-Object System.Windows.Controls.StackPanel
    $Parent.addChild($NewChild)

    return $NewChild
}

Function Add-GroupBox($Parent,$header)
{
    $NewChild = New-Object System.Windows.Controls.GroupBox
    $NewChild.Header = $header
    $Parent.addChild($NewChild)
    
    return $NewChild
}
#endregion Fonctions_ajout_contenu

#region Fonctions_recup_infos
Function Get-BasicSysinfo()
{
    Add-Label -Parent $Stack_UserInfo -Content "User Name:`t$env:USERNAME"
    ## Is user in admin local group
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    If ( $IsAdmin )
    {
        Add-Label -parent $Stack_UserInfo -Content "Is Admin:`t$IsAdmin" -color $([System.Windows.Media.Brushes]::Crimson)
    }
    Else
    {
        Add-Label -parent $Stack_UserInfo -Content "Is Admin:`t$IsAdmin" -color $([System.Windows.Media.Brushes]::LightGreen)
    }

    $bootInfo = Get-WmiObject -Class Win32_OperatingSystem
    $bootInfoLastBoot = [System.Management.ManagementDateTimeconverter]::ToDateTime($bootInfo.lastbootuptime)
    $u = New-TimeSpan -Start $bootInfoLastBoot -End $(get-date)
    $BootUpTime = "$($u.days) day(s), $($u.hours) hour(s), $($u.Minutes) minute(s)"

    Add-Label -Parent $Stack_SysInfo -Content "Computer Name:`t$env:COMPUTERNAME" -test $True
    Add-Label -Parent $Stack_SysInfo -Content "Domain Name:`t$env:USERDOMAIN"
    Add-Label -Parent $Stack_SysInfo -Content "Last Boot Date:`t$($bootInfoLastBoot.ToString('dd/MM/yyyy hh:mm:ss'))"
    Add-Label -Parent $Stack_SysInfo -Content "Current Uptime:`t$BootUpTime"
    Add-Label -Parent $Stack_SysInfo -Content "OS Caption:`t$($bootInfo.Caption)"
    Add-Label -Parent $Stack_SysInfo -Content "OS Version:`t$($bootInfo.Version)"
    Add-Label -Parent $Stack_SysInfo -Content "OS Build Number:`t$($bootInfo.BuildNumber)"
    Add-Label -Parent $Stack_SysInfo -Content "OS Architecture:`t$($bootInfo.OSArchitecture)"
}

Function Get-DiskInfo()
{
    $diskInfos = Get-WmiObject -Class win32_LogicalDisk -Filter "DriveType=3"
    Foreach($d in $diskInfos)
    {
        Add-Label -Parent $Stack_DisksInfo -Content "Disk: $($d.DeviceId)`tSize: $([Math]::Round(($d.Size/1Gb),2)) Go`tFreeSpace: $([Math]::Round(($d.FreeSpace/1gb),2)) Go " -gradient $([Math]::Round($d.FreeSpace/$d.Size,2))
    }
}

Function Get-ProxyInfo()
{
    ## Netsh proxy info
    Foreach ($Line in $(Invoke-Expression "netsh winhttp show proxy"))
    {
        If ( $Line -match "^\s*.*\.$" )
        {
            Add-Label -Parent $Stack_Proxy_Info -Content "WinHTTP Configuration:`t$($Line.trim())"
        } 
    }

    ## IE Proxy info
    $IeProxy = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').autoconfigurl
    If ( $IeProxy )
    {
        Add-Label -Parent $Stack_Proxy_Info -Content "Internet Explorer proxy:`t$IeProxy"
    }
    Else
    {
        Add-Label -Parent $Stack_Proxy_Info -Content "Internet Explorer proxy :`tIE Proxy seems Disabled" -Color  $([System.Windows.Media.Brushes]::Crimson)
    }
}

Function Get-NetInfo()
{
    $a = Get-NetworkCardInfo | Where-Object status -eq 'Up'
    Foreach ( $card in $a )
    {
        ## Card info
        $x = Add-TabItem -Parent $TabNet -Header "$($card.Name)"
        $v = Add-StackPanel -Parent $x 
        $y = Add-GroupBox -Parent $v -Header "NetWork Card:"
        $z = Add-StackPanel -Parent $y

        Add-Label -Parent $z -Content "Connection:`t$($card.Name)"
        Add-Label -Parent $z -Content "Connection Type:`t$($card.Type)"
        Add-Label -Parent $z -Content "Interface:`t$($card.Description)"
        Add-Label -Parent $z -Content "Speed:`t`t$($card.Speed)"
        Add-Label -Parent $z -Content "MTU:`t`t$($card.Mtu)"

        ## DHCP info
        $w = Add-GroupBox -Parent $v -Header "DHCP infos:"
        $z = Add-StackPanel -Parent $w
        If ( $card.IsDHCPEnabled ) {
            Add-Label -Parent $z -Content "Is DHCP Enabled:`t$($card.IsDHCPEnabled)" -color $([System.Windows.Media.Brushes]::LightGreen)
            Add-Label -Parent $z -Content "Obtention bail:`t$($card.DhcpLeaseObtainedDate)"
            Add-Label -Parent $z -Content "Expiration bail:`t$($card.DhcpLeaseExpirationDate)"
            Add-Label -Parent $z -Content "DHCP Server:`t$($card.DhcpServerAddress)"
        } Else {
            Add-Label -Parent $z -Content "Is DHCP Enabled:`t$($card.IsDHCPEnabled)" -color $([System.Windows.Media.Brushes]::Crimson)
            Add-Label -Parent $z -Content "Obtention bail:`t-"
            Add-Label -Parent $z -Content "Expiration bail:`t-"
            Add-Label -Parent $z -Content "DHCP Server:`t-"
        }

        ## IP Infos
        $w = Add-GroupBox -Parent $v -Header "IPv4 infos:"
        $z = Add-StackPanel -Parent $w
        If ( !$card.IsAPIPA ) {
            Add-Label -Parent $z -Content "Is Address APIPA:`t$($card.IsApipa)" -color $([System.Windows.Media.Brushes]::LightGreen)
        } Else {
            Add-Label -Parent $z -Content "Is Address APIPA:`t$($card.IsApipa)" -color $([System.Windows.Media.Brushes]::Crimson)
        }
        Add-Label -Parent $z -Content "IP Address:`t$($card.Ip)"
        Add-Label -Parent $z -Content "Mask Address:`t$($card.Mask)"
        Add-Label -Parent $z -Content "GateWay Address:`t$($card.GatewayAddresses)"

        ## Wifi Infos
        If ( $Card.Type -eq [System.Net.NetworkInformation.NetworkInterfaceType]::Wireless80211 ) {
            $w = Add-GroupBox -Parent $v -Header "Wifi infos:"
            $z = Add-StackPanel -Parent $w

            Add-Label -Parent $z -Content "Wifi Network:`t$($card.WifiNetwork)"
            Add-Label -Parent $z -Content "Wifi SSID:`t$($card.WifiSSID)"
            Add-Label -Parent $z -Content "Wifi Strength:`t$($card.WifiSignal)"
        }
        #>
    }
}

Function Get-HostFile()
{
    $x = Add-TabItem -Parent $TabNet -Header "Host File"
    $v = Add-StackPanel -Parent $x
    $y = Add-GroupBox -Parent $v -Header "Host File Entries:"
    $z = Add-StackPanel -Parent $y
    $HostFile = Get-Content C:\windows\System32\drivers\etc\hosts
    #$HostFile = Get-Content C:\Users\pchasles\Desktop\GuiSysInfo\host.txt
    $i = 0
    Foreach ( $Line in $HostFile )
    {
        If ( $Line -match "(?<=^)(\d{1,3}\.){3}\d{1,3}" )
        {
            $i++
            Add-Label -parent $z -content $Line
        }
    }
    If ( $i -eq 0 )
    {
        Add-Label -parent $z -content "No Entries Detected"
    }
}

Function Get-SCCMInfo2()
{
    $a = Get-WmiObject -Namespace "root\ccm" -Class ccm_client | Select-Object clientid
    $b = Get-WmiObject -Namespace "root\ccm" -Class sms_client | Select-Object ClientVersion
    Add-Label -parent $Stack_Sccm_Info -content "SCCM Client Guid:`t$(($a.ClientId).replace('GUID:',''))" -width 400
    Add-Label -parent $Stack_Sccm_Info -content "SCCM Client Version:`t$($b.ClientVersion)" -width 400
}

Function Get-SCCMInfo()
{
    $CPAppletMGR = new-object -ComObject CPApplet.CPAppletmgr
    $ClientInfo = $CPAppletMGR.GetClientProperties()
    Add-Label -parent $Stack_Sccm_Info -content "SCCM Client Version:`t$($ClientInfo.item(1).value)" -width 400
    Add-Label -parent $Stack_Sccm_Info -content "SCCM Client Guid:`t$(($ClientInfo.item(5).value).replace('GUID:',''))" -width 400
    Add-Label -parent $Stack_Sccm_Info -content "SCCM Client current MP:`t$(($ClientInfo.item(2).value))" -width 400
}

Function Get-FireWallInfo()
{
    #write-host "lol firewall"
    $FWprofileTypes = @{1=”Domain”; 2=”Private” ; 4=”Public”}
    $FwObject = New-object –comObject HNetCfg.FwPolicy2
    Foreach( $Profil in $FWprofileTypes.GetEnumerator() )
    {
        If ( $($FwObject.FirewallEnabled($Profil.Name)) )
        {
            Add-Label -parent $Stack_FireWall_Info -content "$($Profil.Value) profil:`tON"
        }
        Else
        {
            Add-Label -parent $Stack_FireWall_Info -content "$($Profil.Value) profil:`tOFF"
        }
    }
}

Function Get-RebootPending()
{
    $p = Get-PendingReboot | Select-Object rebootpending,cbservicing,windowsupdate,ccmclientsdk,pendcomputerrename,pendfilerename
    If( !$p.rebootPending )
    {
        Add-Label -parent $Stack_Reboot_Info -content "Reboot Pending:`t$($p.rebootPending)" -Color $([System.Windows.Media.Brushes]::LightGreen)
    }
    Else
    {
        Add-Label -parent $Stack_Reboot_Info -content "Reboot Pending:`t$($p.rebootPending)" -Color $([System.Windows.Media.Brushes]::Crimson)
        If ( $p.CBServicing ) { Add-Label -parent $Stack_Reboot_Info -content "Reboot CBServicing:`t$($p.CBServicing)" }
        If ( $p.WindowsUpdate ) { Add-Label -parent $Stack_Reboot_Info -content "Reboot WindowsUpdate:`t$($p.WindowsUpdate)" }
        If ( $p.PendComputerRename ) { Add-Label -parent $Stack_Reboot_Info -content "Reboot ComputerRename:`t$($p.PendComputerRename)" } 
        If ( $p.PendFileRename ) { Add-Label -parent $Stack_Reboot_Info -content "Reboot FileRename:`t$($p.PendFileRename)" }
    }
}

Function Get-ChildContentText($name,$object)
{
    $String = "$Name"

    Foreach ( $Child in $Object.children )
    {   
        $string = $string + "`n" + ($($Child.Content -replace ":\t",": ")).replace("\t"," ")
    }
    return $string
}

Function Get-ContentRecurse($parent){
    If ($parent -is [System.Windows.Controls.TabControl]){
        Foreach ( $item in $parent.Items ) {
            Get-ContentRecurse $Item
        }
    }

    If ($parent -is [System.Windows.Controls.TabItem]){
        Foreach ( $item in $parent.content ) {
            Get-ContentRecurse $Item
        }
    }

    If ($parent -is [System.Windows.Controls.GroupBox]){
        Get-ContentRecurse $Parent.Content
    }

    If ($parent -is [System.Windows.Controls.StackPanel]){
        Foreach ( $Child in $Parent.Children ) {
            Get-ContentRecurse $Child
        }
    }

    If ($parent -is [System.Windows.Controls.Grid]){
        Foreach ( $Child in $Parent.Children ) {
            Get-ContentRecurse $Child
        }
    }

    If ($parent -is [System.Windows.Controls.Label]){
        $($parent.Content) >> c:\temp\arflol2.txt
    }
}

Function Invoke-GPResult()
{
    $newRunspace =[runspacefactory]::CreateRunspace()
    $newRunspace.ApartmentState = "STA"
    $newRunspace.ThreadOptions = "ReuseThread"         
    $newRunspace.Open()
    $newRunspace.SessionStateProxy.SetVariable("syncHash",$Global:syncHash)
    If ( $Global:syncHash.GrpBox_GPO_Info.Header -eq "Gpresult Return Info" )
    {
        $Global:syncHash.GrpBox_GPO_Info.Header = "Gpresult Return Info, working in background, please wait.."
        $Global:syncHash.GrpBox_GPO_Info.ToolTip = "Gpresult is run in a background process, this may take a while, please wait..."
    }

    $GPResultCode = {
        $Global:syncHash.Menu_Copy.Dispatcher.invoke([action]{$Global:syncHash.Menu_Copy.IsEnabled = $False})
        $Global:syncHash.Menu_Reload.Dispatcher.invoke([action]{$Global:syncHash.Menu_Reload.IsEnabled = $False})
        gpresult.exe /x "$($env:TEMP)\gpResult.xml"
        [xml]$xml = get-content "$($env:TEMP)\gpResult.xml"
        $AppliedGpos = $xml.Rsop.UserResults.gpo | Where-Object {($_.isvalid -eq $True) -and ($_.AccessDenied -eq $false)}
        $RefusedGpos = $xml.Rsop.UserResults.gpo | Where-Object {($_.isvalid -eq $True) -and ($_.AccessDenied -eq $True)}
        $Global:syncHash.GpoApplied = "Applied GPOS:`n"
        $Global:syncHash.GpoRefused = "Refused GPOS:`n"
        $AppliedGpos.name | ForEach-Object{$Global:syncHash.GpoApplied  = $Global:syncHash.GpoApplied +"`t$_ `n"}
        $RefusedGpos.Name | ForEach-Object{$Global:syncHash.GpoRefused  = $Global:syncHash.GpoRefused +"`t$_ `n"}
        $Global:syncHash.Stack_GPO_Info.Dispatcher.invoke([action]{
            $Global:syncHash.Stack_GPO_Info.ToolTip = $null
            $NewChild1 = New-Object System.Windows.Controls.Label
            $NewChild1.Content = $Global:syncHash.GpoApplied
            $NewChild1.Width = 370
            $NewChild2 = New-Object System.Windows.Controls.Label
            $NewChild2.Content = $Global:syncHash.GpoRefused
            $NewChild2.Width = 370
            $Global:syncHash.Stack_GPO_Info.Children.Add($NewChild1)
            $Global:syncHash.Stack_GPO_Info.Children.Add($NewChild2)
            $Global:syncHash.GrpBox_GPO_Info.Header = "Gpresult Return Info"
            $Global:syncHash.GrpBox_GPO_Info.ToolTip = $null
        })

        $Global:syncHash.Menu_Copy.Dispatcher.invoke([action]{$Global:syncHash.Menu_Copy.IsEnabled = $True })
        $Global:syncHash.Menu_Reload.Dispatcher.invoke([action]{$Global:syncHash.Menu_Reload.IsEnabled = $True })
        Remove-Item -Path "$($env:TEMP)\gpResult.xml"
        $Global:syncHash.InvokeGpResult.EndInvoke()
        $Global:syncHash.Host.runspace.events.GenerateEvent("GpResultEvent",$null,$null,"test")
    }
    $Global:syncHash.InvokeGpResult = [powershell]::Create()
    $Global:syncHash.InvokeGpResult.addScript($GPResultCode)
    $Global:syncHash.InvokeGpResult.runspace = $newRunspace
    #$Global:syncHash.InvokeGpResult.BeginInvoke()
    $Global:syncHash.AsyncGPO = $Global:syncHash.InvokeGpResult.BeginInvoke()
}

Function Invoke-Tracert($a){
    $newRunspaceT = [runspacefactory]::CreateRunspace()
    $newRunspaceT.ApartmentState = "STA"
    $newRunspaceT.ThreadOptions = "ReuseThread"
    $newRunspaceT.Open()
    $newRunspaceT.SessionStateProxy.SetVariable("syncHash",$Global:syncHash)
    $TracertCode = {
        Param ($Param1)
        $Global:syncHash.Stack_NetInfo_Tracert.Dispatcher.invoke([action]{
            $Global:syncHash.TextBox_Tracert.IsEnabled = $False
            $Global:syncHash.Button_Tracert.IsEnabled = $False
        })
        $i = 0
        tracert.exe $Param1 | ForEach-Object{
            If ($_ -match "^\s+\d{1,2}"){
                $i++
                $split = [regex]::split($_.trim(), "\s{2,}")
                $Properties = [Ordered]@{
                    Hop    = $split[0]
                    First  = $split[1]
                    Second = $split[2]
                    Third  = $split[3]
                    Node   = $split[4]
                }
                $Object = New-Object psobject -Property $Properties
                $Global:syncHash.ListView_Tracert.Dispatcher.invoke([action]{
                    $Global:syncHash.ListView_Tracert.Items.Add($Object)
                    $Global:syncHash.ListView_Tracert.ScrollIntoView($Global:syncHash.ListView_Tracert.Items[$Global:syncHash.ListView_Tracert.Items.count-1])
                })
            }
        }
        $Global:syncHash.Stack_NetInfo_Tracert.Dispatcher.invoke([action]{
            $Global:syncHash.TextBox_Tracert.IsEnabled = $True
            $Global:syncHash.Button_Tracert.IsEnabled = $True
            $Global:syncHash.Button_Stop_Tracert.IsEnabled = $False
            $Global:syncHash.Button_Clear_Tracert.Visibility = [System.Windows.Visibility]::Visible
        })
        $Global:syncHash.Host.runspace.events.GenerateEvent("TracertEvent",$null,$null,"test")
    }
    $Global:syncHash.InvokeTracert = [powershell]::Create()
    #$Global:syncHash.InvokeTracert($TextBox_Tracert.Text)
    $Global:syncHash.InvokeTracert.AddScript($TracertCode)
    $Global:syncHash.InvokeTracert.AddParameter('Param1',$TextBox_Tracert.Text) 
    $Global:syncHash.InvokeTracert.runspace = $newRunspaceT
    $Global:syncHash.AsyncTracert = $Global:syncHash.InvokeTracert.BeginInvoke()
}

Function Invoke-Ping($a){
    $newRunspaceT = [runspacefactory]::CreateRunspace()
    $newRunspaceT.ApartmentState = "STA"
    $newRunspaceT.ThreadOptions = "ReuseThread"
    $newRunspaceT.Open()
    $newRunspaceT.SessionStateProxy.SetVariable("syncHash",$Global:syncHash)
    $PingCode = {
        Param ($Param1)
        Try {
            Test-Connection -ComputerName $Param1 -count 15 -ErrorAction Stop | ForEach-Object {
                $Properties = [Ordered]@{
                    Address    = $_.Address
                    IPV4Address  = $_.IPV4Address
                    BufferSize = $_.BufferSize
                    ReplySize  = $_.ReplySize
                    ResponseTime   = $_.ResponseTime
                }
                $Object = New-Object psobject -Property $Properties
                $Global:syncHash.ListView_Ping.Dispatcher.invoke([action]{
                    $Global:syncHash.ListView_Ping.Items.Add($Object)
                    $Global:syncHash.ListView_Ping.ScrollIntoView($Global:syncHash.ListView_Ping.Items[$Global:syncHash.ListView_Ping.Items.count-1])
                })
            }
        }Catch{
            $Properties = [Ordered]@{
                Address    = $param1
                IPV4Address  = "Error"
                BufferSize = "Error"
                ReplySize  = "Error"
                ResponseTime   = "Error"
            }
            $Object = New-Object psobject -Property $Properties
            $Global:syncHash.ListView_Ping.Dispatcher.invoke([action]{
                $Global:syncHash.ListView_Ping.Items.Add($Object)
                $Global:syncHash.ListView_Ping.ScrollIntoView($Global:syncHash.ListView_Ping.Items[$Global:syncHash.ListView_Ping.Items.count-1])
            })
        }
        $Global:syncHash.Stack_NetInfo_Ping.Dispatcher.invoke([action]{
            $Global:syncHash.TextBox_Ping.IsEnabled = $True
            $Global:syncHash.Button_Ping.IsEnabled = $True
            $Global:syncHash.Button_Stop_Ping.IsEnabled = $False
            $Global:syncHash.Button_Clear_Ping.Visibility = [System.Windows.Visibility]::Visible
        })
        $Global:syncHash.Host.runspace.events.GenerateEvent("PingEvent",$null,$null,"test")
    }

    $Global:syncHash.InvokePing = [powershell]::Create()
    $Global:syncHash.InvokePing.AddScript($PingCode)
    $Global:syncHash.InvokePing.AddParameter('Param1',$TextBox_ping.Text) 
    $Global:syncHash.InvokePing.runspace = $newRunspaceT
    $Global:syncHash.AsyncPing = $Global:syncHash.InvokePing.BeginInvoke()
}
#endregion region Fonctions_recup_infos

#region Lecture_xaml_et_creation_variables
$reader=(New-Object System.Xml.XmlNodeReader $xaml)
$Window=[Windows.Markup.XamlReader]::Load($reader) 
#Connect to Controls 
$xaml.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]")  | ForEach-Object {
    New-Variable  -Name $_.Name -Value $Window.FindName($_.Name) -Force
}
#endregion Lecture_xaml_et_creation_variables

#region General_Controls_Events
$Window.Add_Loaded({
    $syncHash.Menu_Reload = $Menu_Reload

    $syncHash.GrpBox_Tracert_Result = $GrpBox_Tracert_Result
    $syncHash.ListView_Tracert = $ListView_Tracert
    $GrpBox_Tracert_Result.Visibility = [System.Windows.Visibility]::Collapsed
    $Button_Clear_Tracert.Visibility = [system.windows.Visibility]::Hidden
    $Button_Stop_Tracert.IsEnabled = $False
    $syncHash.Button_Stop_Tracert = $Button_Stop_Tracert
    $syncHash.Button_Tracert = $Button_Tracert
    $syncHash.TextBox_Tracert = $TextBox_Tracert
    $syncHash.Stack_NetInfo_Tracert = $Stack_NetInfo_Tracert

    $syncHash.ListView_Ping = $ListView_Ping
    $GrpBox_Ping_Result.Visibility = [System.Windows.Visibility]::Collapsed
    $Button_Clear_Ping.Visibility = [system.windows.Visibility]::Hidden
    $Button_Stop_Ping.IsEnabled = $False
    
    $syncHash.Button_Ping = $Button_Ping
    $syncHash.TextBox_Ping = $TextBox_Ping
    $syncHash.Button_Stop_Ping = $Button_Stop_Ping
    $syncHash.Button_Clear_Ping = $Button_Clear_Ping
    $syncHash.Stack_NetInfo_Ping = $Stack_NetInfo_Ping

    $syncHash.GridNode = $GridNode
    
    $SyncHash.Stack_Tracert_Results = $Stack_Tracert_Results
    
    $syncHash.Stack_GPO_Info = $Stack_GPO_Info
    $syncHash.GrpBox_GPO_Info = $GrpBox_GPO_Info
    $syncHash.GrpBox_GPO_Info.ToolTip = "Gpresult is run in a background process, this may take a while, please wait..."
    $syncHash.Menu_Copy = $Menu_Copy

    Invoke-GPResult

    ## LastBoot + Uptime
    Get-BasicSysinfo

    ## Disk(s) Infos
    Get-DiskInfo

    ## NetWork Infos
    Get-NetInfo

    ## Proxy Infos
    Get-ProxyInfo

    ## Host file Info
    Get-HostFile

    ## FireWall Info
    Get-FireWallInfo

    ## Reboot Info
    Get-RebootPending

    ## SCCM Client Info
    Get-SCCMInfo
})

## Quand on focus sur le réseau on recup les infos
## Trouver un moyen pour le faire une seule fois
$Tab_Reseau.Add_Gotfocus({
})

$Tab_Others.Add_Gotfocus({
})

$TextBox_Tracert.Add_Gotfocus({
    If ( $TextBox_Tracert.Text -eq "Enter Ip/Dns Name and click Start Tracert..." ) {
        $TextBox_Tracert.Text = ""
    }
})

$TextBox_Tracert.Add_Lostfocus({
    If ( $TextBox_Tracert.Text -eq "" ) {
        $TextBox_Tracert.Text = "Enter Ip/Dns Name and click Start Tracert..."
    }
})

$TextBox_Ping.Add_Gotfocus({
    If ( $TextBox_Ping.Text -eq "Enter Ip/Dns Name and click Start Ping..." ) {
        $TextBox_Ping.Text = ""
    }
})

$TextBox_Ping.Add_Lostfocus({
    If ( $TextBox_Ping.Text -eq "" ) {
        $TextBox_Ping.Text = "Enter Ip/Dns Name and click Start Ping..."
    }
})

$Button_Tracert.Add_Click({
    If($ListView_Tracert.Items.count -gt 0) { $Button_Clear_Tracert.Visibility = [System.Windows.Visibility]::Hidden ; $ListView_Tracert.Items.Clear() }
    $GrpBox_Tracert_Result.Visibility = [System.Windows.Visibility]::Visible
    $TextBox_Tracert.IsEnabled = $False
    $Button_Tracert.IsEnabled = $False
    Invoke-Tracert $TextBox_Tracert.Text
    $Button_Stop_Tracert.IsEnabled = $True
})

$Button_Stop_Tracert.Add_Click({
    ## Kill du tracert via generation de l'event
    #$Global:syncHash.Host.runspace.events.GenerateEvent("TracertEvent",$null,$null,"test")
    $Global:syncHash.InvokeTracert.runspace.close()
    $Global:syncHash.InvokeTracert.runspace.Dispose()
    $Global:syncHash.InvokeTracert = $null
    $Button_Tracert.IsEnabled = $True
    $Button_Clear_Tracert.Visibility = [system.windows.Visibility]::Visible
    $TextBox_Tracert.IsEnabled = $True
    $Button_Stop_Tracert.IsEnabled = $False
})

$Button_Clear_Tracert.Add_Click({
    $ListView_Tracert.items.clear()
    $Button_Clear_Tracert.Visibility = [system.windows.Visibility]::Hidden
    $GrpBox_Tracert_Result.Visibility = [System.Windows.Visibility]::Collapsed
})

$Button_Ping.Add_Click({
    If($ListView_Ping.Items.count -gt 0) { $Button_Clear_Ping.Visibility = [System.Windows.Visibility]::Hidden ; $ListView_Ping.Items.Clear() }
    $GrpBox_Ping_Result.Visibility = [System.Windows.Visibility]::Visible
    $TextBox_Ping.IsEnabled = $False
    $Button_Ping.IsEnabled = $False
    Invoke-Ping $TextBox_Ping.Text
    $Button_Stop_Ping.IsEnabled = $True
})

$Button_Stop_Ping.Add_Click({
    ## Kill du tracert via generation de l'event
    #$Global:syncHash.Host.runspace.events.GenerateEvent("TracertEvent",$null,$null,"test")
    $Global:syncHash.InvokePing.runspace.close()
    $Global:syncHash.InvokePing.runspace.Dispose()
    $Global:syncHash.InvokePing = $null
    $Button_Ping.IsEnabled = $True
    $Button_Clear_Ping.Visibility = [system.windows.Visibility]::Visible
    $TextBox_Ping.IsEnabled = $True
    $Button_Stop_Ping.IsEnabled = $False
})

$Button_Clear_Ping.Add_Click({
    $ListView_Ping.items.clear()
    $Button_Clear_Ping.Visibility = [system.windows.Visibility]::Hidden
    $GrpBox_Ping_Result.Visibility = [System.Windows.Visibility]::Collapsed
})
#endregion General_Controls_Events

#region Menu_Controls
$Menu_Reload.Add_Click({
    ## Delete netinfo controls
    If( $Stack_NetCardInfo.Children.Count -gt 0 )
    {
        $i = $Stack_Info_Dhcp.children.count; while($i -gt 0){ $i--; $Stack_Info_Dhcp.children.RemoveAt($i) }
        $i = $Stack_NetCardInfo.children.count; while($i -gt 0){ $i--; $Stack_NetCardInfo.children.RemoveAt($i) }
        $i = $Stack_NetInfo_Ip.children.count; while($i -gt 0){ $i--; $Stack_NetInfo_Ip.children.RemoveAt($i) }
        $i = $Stack_NetInfo_Test.children.count; while($i -gt 0){ $i--; $Stack_NetInfo_Test.children.RemoveAt($i) }
        Get-Netinfo
    }

    ## Delete Sysinfo controls
    If( $Stack_SysInfo.Children.count -gt 0 )
    {
        $y = $Stack_UserInfo.children.count; while($y -gt 0){ $y--; $Stack_UserInfo.children.RemoveAt($y) }
        $i = $Stack_SysInfo.children.count; while($i -gt 0){ $i--; $Stack_SysInfo.children.RemoveAt($i) }
        Get-BasicSysinfo
    }

    ## Delete Diskinfo controls
    If( $Stack_DisksInfo.Children.count -gt 0 )
    {
        $i = $Stack_DisksInfo.children.count; while($i -gt 0){ $i--; $Stack_DisksInfo.children.RemoveAt($i) }
        Get-DiskInfo
    }

    ## Delete Proxyinfo controls
    If( $Stack_Proxy_Info.children.count -gt 0 )
    {
        $i = $Stack_Proxy_Info.children.count; while($i -gt 0){ $i--; $Stack_Proxy_Info.children.RemoveAt($i) }
        Get-ProxyInfo
    }

    ## Delete HostFile controls
    If( $Stack_HostFile_Info.children.count -gt 0 )
    {
        $i = $Stack_HostFile_Info.children.count; while($i -gt 0){ $i--; $Stack_HostFile_Info.children.RemoveAt($i) }
        Get-HostFile
    }

    ## Delete FireWall controls
    If( $Stack_FireWall_Info.children.count -gt 0 )
    {
        $i = $Stack_FireWall_Info.children.count; while($i -gt 0){ $i--; $Stack_FireWall_Info.children.RemoveAt($i) }
        Get-FireWallInfo
    }

    ## Delete Reboot controls
    If( $Stack_Reboot_Info.children.count -gt 0 )
    {
        $i = $Stack_Reboot_Info.children.count; while($i -gt 0){ $i--; $Stack_Reboot_Info.children.RemoveAt($i) }
        Get-RebootPending
    }
    
    ## Delete SCCM Client controls
    If( $Stack_SCCM_Info.children.count -gt 0 )
    {
        $i = $Stack_SCCM_Info.children.count; while($i -gt 0){ $i--; $Stack_SCCM_Info.children.RemoveAt($i) }
        Get-SCCMInfo
    }

    If( $Global:syncHash.Stack_GPO_Info.Children.count -gt 0)
    {
        $i = $Global:syncHash.Stack_GPO_Info.children.count; while($i -gt 0){ $i--; $Global:syncHash.Stack_GPO_Info.children.RemoveAt($i) }
        Invoke-GPResult
    }

    ## Desactivation du tab de test et retour sur le tag general
    #$Tab_Test.IsEnabled = $False
    $MainTab.SelectedIndex = 0
})

$Menu_Copy.Add_Click({
    Get-ContentRecurse $MainTab
    <#
    $ToClip = ""
    $ToClip = $(Get-ChildContentText "== Infos Sys ==" -object $Stack_SysInfo)
    $ToClip = $ToClip + "`n`n" + $(Get-ChildContentText "== Reboot Pending ==" -object $Stack_Reboot_Info)
    $ToClip = $ToClip + "`n`n" + $(Get-ChildContentText "== Disk(s) Info ==" -object $Stack_DisksInfo)
    $ToClip = $ToClip + "`n`n" + $(Get-ChildContentText "== General IP Info ==" -object $Stack_NetInfo_Ip)
    $ToClip = $ToClip + "`n`n" + $(Get-ChildContentText "== DHCP Info ==" -object $Stack_NetCardInfo)
    $ToClip = $ToClip + "`n`n" + $(Get-ChildContentText "== FireWall Info ==" -object $Stack_FireWall_Info)
    $ToClip = $ToClip + "`n`n" + $(Get-ChildContentText "== Proxy Info ==" -object $Stack_Proxy_Info)
    $ToClip = $ToClip + "`n`n" + $(Get-ChildContentText "== Host File Info ==" -object $Stack_HostFile_Info)
    $ToClip = $ToClip + "`n`n" + $(Get-ChildContentText "== Basic Network Tests ==" -object $Stack_NetInfo_Test)
    $ToClip = $ToClip + "`n`n" + $(Get-ChildContentText "== SCCM Client Info ==" -object $Stack_SCCM_Info)

    [Windows.Forms.Clipboard]::Clear()
    [Windows.Forms.Clipboard]::SetText($ToClip.replace("`n","`r`n"))
    #>

})
#endregion Menu_Controls

$Null = $Window.ShowDialog()
}


$newRunspace =[runspacefactory]::CreateRunspace()
$newRunspace.ApartmentState = "STA"
$newRunspace.ThreadOptions = "ReuseThread"         
$newRunspace.Open()
$newRunspace.SessionStateProxy.SetVariable("syncHash",$Global:syncHash)

$PsRunSpace = [powershell]::Create()
$PsRunSpace.AddScript($Main)
$PsRunSpace.Runspace = $newRunspace
$PsRunSpace.BeginInvoke()