# Script Name: Processes_to_Bad_ips.ps1
# Purpose: Map what process is talking with suspicious IP adresses


$Processes = @{}
Get-Process -IncludeUserName | ForEach-Object {
    $Processes[$_.Id] = $_
}

$listing = Get-NetTCPConnection | 
Select-Object -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, 
@{Name="ProcessName";Expression={$Processes[[int]$_.OwningProcess].ProcessName}},
@{Name="UserName";Expression={$Processes[[int]$_.OwningProcess].UserName}}


foreach($line in $listing){
    
    $states = $line.State
    $proc_name = $line.ProcessName
    $remote_ip = $line.RemoteAddress
    $remote_port = $line.RemotePort

        if($states -match "Established" -and $remote_ip -notmatch '127.0.0.1'){
    
            $gen_url = "https://otx.alienvault.com/api/v1/indicators/IPv4/$remote_ip/general"
            $malware_url = "https://otx.alienvault.com/api/v1/indicators/IPv4/$ip_add/malware" 
            
            $response = Invoke-RestMethod -Method GET -Uri $gen_url
            $malware__response = Invoke-RestMethod -Method GET -Uri $malware_url
               
            $pulses = $response.pulse_info.count
            $malware = $malware__response.count

            if($pulses -eq 0) {

    } else { 
    
        if($states -match "Established" -and $remote_ip -notmatch '127.0.0.1'){
        
            $hostname = [System.Net.Dns]::GetHostEntry($remote_ip).HostName
            Write-Host "`t$proc_name is communicating with a suspicious IP that has been reported $pulses times to AlienVault." 
            Write-Host "`t$proc_name is communicating with $hostname [$remote_ip] over port $remote_port"
            Write-Host "`t`t[$remote_ip] is associated with $malware counts of malware related files"
            Write-Host ""

            }
    
    }
    
     
  }
}
