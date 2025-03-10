# Script Name: Processes_to_IP_Reputation.ps1
# Purpose: Map what process is talking with suspicious IP adresses according to otx.alienvault.com
# Please note, this must be ran with elevated privileges.


$Processes = @{}
Get-Process -IncludeUserName | ForEach-Object {
    $Processes[$_.Id] = $_
}

$listing = Get-NetTCPConnection | 
Select-Object -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, 
@{Name="ProcessName";Expression={$Processes[[int]$_.OwningProcess].ProcessName}},
@{Name="UserName";Expression={$Processes[[int]$_.OwningProcess].UserName}}
Write-Host ""
Write-Host "============================================ Established Connecitons Details ========================"
Write-Host "`tStatus `t`tProcess Name `t`tRemote IP `t`tRemote Port `tReported `t# of malware files"
Write-Host "-----------------------------------------------------------------------------------------------------"

foreach($line in $listing){
    
    $states = $line.State
    $proc_name = $line.ProcessName
    $remote_ip = $line.RemoteAddress
    $remote_port = $line.RemotePort

        if($states -match "Established" -and $remote_ip -notmatch '127.0.0.1'){
    
            $gen_url = "https://otx.alienvault.com/api/v1/indicators/IPv4/$remote_ip/general"
            $malware_url = "https://otx.alienvault.com/api/v1/indicators/IPv4/$remote_ip/malware" 
            
            $response = Invoke-RestMethod -Method GET -Uri $gen_url
            $malware__response = Invoke-RestMethod -Method GET -Uri $malware_url
               
            $pulse_count = $response.pulse_info.count
            $reputation = $response.reputation
            $malware = $malware__response.count

            if($pulse_count -eq 0) {
            $KNownGood_cnt++
            #$hostname = [System.Net.Dns]::GetHostEntry($remote_ip).HostName 
            Write-Host "`tKnown Good `t$proc_name `t`t[$remote_ip] `t`t$remote_port `t$pulse_count `t$malware"
                                                 
    } elseif($pulse_count -eq 1 ) {
            $Stale_ioc_cnt++
            #$hostname = [System.Net.Dns]::GetHostEntry($remote_ip).HostName
            Write-Host "`tfurther investigation required `t$proc_name `t`t[$remote_ip] `t`t$remote_port `t$pulse_count `t$malware"
            
    }elseif($pulse_count -gt 1) { 
            $suspicious_cnt++
            #$hostname = [System.Net.Dns]::GetHostEntry($remote_ip).HostName
            Write-Host "`tSuspicious `t$proc_name `t`t[$remote_ip] `t`t$remote_port `t$pulse_count `t$malware"
     
    }
     
  }

}


Write-Host ""
Write-Host "======================== Metrics ========================"
Write-Host "Number of Known Good Connections: $KNownGood_cnt"
Write-Host "Number of Could be Stale IoC: $Stale_ioc_cnt"
Write-Host "Number of Suspicious Connections: $suspicious_cnt"

$KNownGood_cnt = 0
$Stale_ioc_cnt = 0
$suspicious_cnt = 0
