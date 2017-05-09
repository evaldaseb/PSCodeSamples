# Date:   16/07/2015
# Author: Evaldas Baltrunas

$computerName = Get-ADComputer -Filter * -SearchBase 'OU=Windows 7,OU=OUName1,DC=SomeDomainName,DC=com'

$timestamp = Get-Date -Format dd_MM_yyyy_HH_mm
$output = @()
foreach ($computer in $computername.Name) {
    $username = $null
    $u = $null
    $status = $null
    $statusForCsvOutput = $null
    $cs = $null

    function Get-PingStatus ($computer) {
	    try {
		    Test-Connection $computer -Count 1 -ErrorAction 'Stop' | Out-Null
		    $ping_ok = $true
	    }
	    catch {
		    $ping_ok = $false
		    Write-Host "No ping!"
	    }
	    Write-Output $ping_ok 
    }

    if (Get-PingStatus $computer) {
        write-host "Querying $computer" -ForegroundColor Yellow
        
        try {
            $cs = gwmi win32_ComputerSystem -ComputerName $computer -ErrorAction Stop | select UserName, Model
            $wmi = $true
        }
        catch {
            $Status = "No Access"
            $wmi = $false
            Write-host "No access to $computer" -ForegroundColor Red
            $username = $null
        }
        
        if ($wmi) {


            if ($cs.UserName) {
                # $u = $cs.UserName
                [int]$i = $cs.UserName.IndexOf("\")
                $u = $cs.UserName.Substring($i + 1)
            }
            else 
            {
                try 
                {
                    $pintProcess = gwmi win32_Process -ComputerName $computer -Filter "Name='pint.exe'" -ErrorAction Stop
                    
                    if ($pintProcess.Count -gt 1) 
                    {
                        foreach ($p in $pintProcess)
                        {
                            $u += $p.GetOwner().User + "/"

                        }
                    }
                    else 
                    {
                        $u = $($pintProcess.GetOwner().User)
                    }
                }
                catch 
                {
                    Write-Warning "$($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
                }
            }
            
            try {
                $fullchargecapacity = (Get-WmiObject -Class "BatteryFullChargedCapacity" -Namespace "ROOT\WMI" -ComputerName $computer -ErrorAction Stop).FullChargedCapacity
                $battery = $true
            }
            catch {
                $battery = $false
                $Status = "Desktop PC"
                $statusForCsvOutput = "Desktop PC"
            }
            
            if ($battery) {
                
                $batteryStatus = gwmi win32_battery -ComputerName $computer | select Availability
                
                try {
                    $designcapacity = (Get-WmiObject -Class "BatteryStaticData" -Namespace "ROOT\WMI" -ComputerName $computer -ErrorAction Stop).DesignedCapacity
                    $batteryStaticData = $true
                }
                catch {
                     $batteryStaticData = $false
                     $Status = "Check manually"
                     $statusForCsvOutput = "Check manually"
                }
                
                if ($batteryStaticData) { 


                    $batteryhealth = ($fullchargecapacity / $designcapacity) * 100
                    if ($batteryhealth -gt 100) {$batteryhealth = 100}
                    $Status = [decimal]::round($batteryhealth)
                
                    $statusForCsvOutput = $Status
                
                    if ($Status -ge 90) { $Status = "<div id=s1>"+$Status+"</div>" }
                    if ($Status -lt 89) { $Status = "<div id=s2>"+$Status+"</div>" }
                    if ($Status -lt 69) { $Status = "<div id=s3>"+$Status+"</div>" }
                
                } #end if $batteryStaticData

                if ($batteryStaticData -eq $false) {
                
                    switch ($cs.model) {
                        
                        "TECRA R950" {
                            $designcapacity = 65000

                            $batteryhealth = ($fullchargecapacity / $designcapacity) * 100
                            if ($batteryhealth -gt 100) {$batteryhealth = 100}
                            $Status = [decimal]::round($batteryhealth)
                
                            $statusForCsvOutput = $Status
                
                            if ($Status -ge 90) { $Status = "<div id=s1>"+$Status+"</div>" }
                            if ($Status -lt 89) { $Status = "<div id=s2>"+$Status+"</div>" }
                            if ($Status -lt 69) { $Status = "<div id=s3>"+$Status+"</div>" }
                        } #end TECRA 950

                        "PORTEGE R930" {
                            $designcapacity = 66000

                            $batteryhealth = ($fullchargecapacity / $designcapacity) * 100
                            if ($batteryhealth -gt 100) {$batteryhealth = 100}
                            $Status = [decimal]::round($batteryhealth)
                
                            $statusForCsvOutput = $Status
                
                            if ($Status -ge 90) { $Status = "<div id=s1>"+$Status+"</div>" }
                            if ($Status -lt 89) { $Status = "<div id=s2>"+$Status+"</div>" }
                            if ($Status -lt 69) { $Status = "<div id=s3>"+$Status+"</div>" }

                        } #end PORTEGE R930

                    } #end select

                } #end if batteryStaticData -eq $false
            
            } #end if battery
        
        } #end if wmi
    }

    else {
        $Status = "No ping"
        $statusForCsvOutput = "No ping"
    }

    $ComputerDescription = Get-ADComputer $computer -Properties Description

    $props = [ordered]@{'Date'=(get-date).ToShortDateString()
                        'Time'=(get-date).ToShortTimeString()
                        'PCName'=$computer
                        'Model'=$cs.model
                        'Status'=$Status
                        'Description'=$ComputerDescription.Description
                        'Logged in user'=$u
    }
    
    # for csv output
    $props1 = [ordered]@{'Date'=(get-date).ToShortDateString()
                         'Time'=(get-date).ToShortTimeString()
                         'PCName'=$computer
                         'Model'=$cs.model
                         'Status'=$statusForCsvOutput
                         'Description'=$ComputerDescription.Description
                         'Logged in user'=$u
    }

    New-Object PSObject -Property $props1 | export-csv $PSScriptRoot\BatteryStatusReport_$timestamp.csv -NoTypeInformation -Append
    
    $output += New-Object PSObject -Property $props
} # end foreach computer

#$t1 = $output[0].Status | Out-String

$html = $output | ConvertTo-Html -Fragment | Out-String

$html = $html.Replace("&lt;","<")
$html = $html.Replace("&gt;",">")

$params = @{'Head'="<title>Battery health status report</title>
            <style>
                   body {font-family:Tahoma;font-size:12px;}
                   table {width:auto}
                   td, th {border:1px solid black;}
                   #s1 {background-color:green;color:black;font-size:12px;}
                   #s2 {background-color:yellow;color:black;font-size:12px;}
                   #s3 {background-color:red;color:black;font-size:12px;}
            </style>"
            'PreContent'="<h1>Battery health status report</h1>"
            'PostContent'=$html  
}

    
ConvertTo-Html @params | Out-File $PSScriptRoot\BatteryStatus.html

$to         = 'SomeEmailAddress@email.com','SomeEmailAddress@email.com'
$bcc        = 'SomeEmailAddress@email.com','SomeEmailAddress@email.com'
$from       = 'SomeEmailAddress@email.com'
$subject    = 'Weekly Report - Battery Status Report for BCPC Laptops'
$SMTPServer = "SMTPServer"
$body       = "Please find attached report on the battery status of the BCPC laptops. <b>Note: This is an automatically generated report and email.</b>"

$EmailSettings = @{'To'        = $to
	               'From'      = $from
	               'Subject'   = $subject   
	               'SMTPServer'= $SMTPServer
                 'Body'      = $Body
                 'bcc'       = $bcc
}

Send-MailMessage @EmailSettings -Attachments $PSScriptRoot\BatteryStatus.html -BodyAsHtml 
