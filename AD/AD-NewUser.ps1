<#	
	.NOTES
	===========================================================================
	 Created on:   	10/04/2016
	 Created by:   	Evaldas Baltrunas
	 Organization: 	
	 Filename:     	Starters.ps1
	===========================================================================
	.DESCRIPTION
		A description of the file.
#>

function Test-AccessToPathsAndFiles
{
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory)]
		[hashtable]$MainProps
	)
	try
	{
		if ((Test-Path $($MainProps.MainPath + '\' + $MainProps.ArchivePath) -ErrorAction Stop) `
		-and (Test-Path $($MainProps.MainPath + '\' + $MainProps.StartersLogsPath) -ErrorAction Stop))
		{
			$access = $true
		}
		else
		{
			$access = $false
		}
	}
	catch
	{
		Add-Content $TmpFile "$($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
		$access = $false
	} #end trycatch
	Write-Output $access
} # end function Test-AccessToPathsAndFiles

function New-GSTTADAccount
{
    [CmdletBinding(SupportsShouldProcess)]
    Param 
    (
        [Parameter(Mandatory)]
        [hashtable]$MainProps,

        [Parameter(Mandatory)]
        [string[]]$StarterFiles
    )
    $script:total = 0 # just to keep a count of how many new accounts we created
    foreach ($file in $StarterFiles)
    {
      Write-Verbose "Working with $file"
      Add-Content -Path $MainLogFile -value "Working with $file"
      # Write-Verbose $($MainProps.MainPath + '\' + $MainProps.ArchivePath + '\' + $file)
      $ImportedFile = import-csv $($MainProps.MainPath + '\' + $MainProps.ArchivePath + '\' + $file)
      foreach ($starter in $ImportedFile)
      {
		    Write-Verbose "$($starter.FirstName) $($starter.LastName)"
		    Add-Content $MainLogFile '-------------------------'
        Add-Content -Path $MainLogFile -value "Working with $($starter.FirstName) $($starter.LastName)"

        if ($starter.PersonID -eq '') 
        {
          Write-Verbose "No PersonID (employeeID) for $($starter.FirstName) $($starter.LastName), account will not be created (or updated)"
          Add-Content $MainLogFile "[Warning] No PersonID (employeeID) for $($starter.FirstName) $($starter.LastName), account will not be created (or updated)"
          $EnoughDetails = $false
        }

        elseif ($starter.FirstName -eq '')
        {
          Write-Verbose "No FirstName for $($starter.FirstName) $($starter.LastName), account will not be created"
          Add-Content $MainLogFile "[Warning] No FirstName for $($starter.FirstName) $($starter.LastName), account will not be created"
          $EnoughDetails = $false
        }

        elseif ($starter.LastName -eq '')
        {
          Write-Verbose "No LastName for $($starter.FirstName) $($starter.LastName), account will not be created"
          Add-Content $MainLogFile "[Warning] No LastName for $($starter.FirstName) $($starter.LastName), account will not be created"
          $EnoughDetails = $false
        }

        elseif ($starter.ManagerEMail -eq '')
        {
          Write-Verbose "No ManagerEMail for $($starter.FirstName) $($starter.LastName), account will not be created"
          Add-Content $MainLogFile "[Warning] No ManagerEMail for $($starter.FirstName) $($starter.LastName), account will not be created"
          $EnoughDetails = $false
        }
            
        else 
        {
          Write-Verbose "We have enough details for $($starter.FirstName) $($starter.LastName) to create a new account"
          Add-Content $MainLogFile "We have enough details for $($starter.FirstName) $($starter.LastName) to create a new account"                    
          $EnoughDetails = $true
        } # end IfElse

        if ($EnoughDetails)
        {
          if ($starter.FirstName.Contains('-'))
          {
            $FirstName = $starter.Firstname.Replace('-',' ')
          }
          else
          {
            $FirstName = $starter.FirstName
          }

          if ($FirstName.Contains(' '))
          {
            $index = $FirstName.IndexOf(' ')
            $FirstName = $FirstName.Remove($index)
          }

          $FirstName = $FirstName -replace '\d|\W', ''
          $LastName  = $starter.LastName -replace '\d|\W', ''
                
          # Write-Verbose "$FirstName $LastName"

          # Check if employeeID or FirstName + LastName already in AD
          if (get-qaduser -SearchAttributes @{employeeid=$starter.PersonID})
          {
            Write-Verbose "$($starter.PersonID) already in AD, not creating new account"
            Add-Content $MainLogFile "[Warning] $($starter.PersonID) already in AD, not creating new account"
				  } # end if employeeID found in AD
          
          # Using LdapFilter and wildcards at the end of names because some accounts created by the help desk
          # have white spaces and names would not match.
          elseif (get-qaduser -LdapFilter "(&(sn=$Lastname*)(givenName=$Firstname*))")
          {
            Write-Verbose "$($starter.FirstName) $($starter.LastName) already in AD, not creating new account"
            Add-Content $MainLogFile "[Warning] $($starter.FirstName) $($starter.LastName) already in AD, not creating new account"
          } # end elseif FirstName+LastName found in AD
				
				  else
				  {
					  Write-Verbose 'No duplicates found in AD, ready to create new account'
					  Add-Content $MainLogFile 'No duplicates found in AD, ready to create new account'

                    # Format OU parameter
                    if (!($starter.ou_path -eq '')) {
                        $oun = ''
                        $ou = $starter.ou_path
                        $a = $ou.Split('\')
                        $i = $a.count-1
                        do {
                            $oun += "OU=$($a[$i]),"
                            $i = $i - 1 
                        }
                        until ($i -lt 0)
                        $oun = $oun + 'OU=OUName,DC=SomeDomainName,DC=com'
                    }
                    else 
                    {
                        $oun = 'OU=AnotherOUName,OU=OUName,DC=SomeDomainName,DC=com'    
                    }
                    # end formatting OU

                    # Making sure SamAccountName is unique.
                    # When creating a new account manually ARS takes care of this but when using
                    # script using first letter + lastname (SamAccountName format) causes problems
                    # if this combination already exists in AD. The account parameter would be left
                    # blank.
                    $SamAccountName = $FirstName.Substring(0,1) + $LastName
                    [int]$i = 0
                    While (Test-SamAccountName -SamAccountName $SamAccountName)
                    {
                        $i = $i + 1
                        $SamAccountName = $FirstName.Substring(0,1) + $LastName + $i
                    }
                    
                    # ARS Policy: LogonName max length in characters: 20
                    # If this is the case, we are not creating an account
                    if ($SamAccountName.Length -gt 20) {
                      Write-Warning 'User LogonName length is greater than 20 characters, ARS policy will not allow this.'
                      Write-Warning 'Review users Firstname and Lastname.'
						          Add-Content $TmpFile '[Warning] User LogonName length is greater than 20 characters, ARS policy will not allow this.'
                      Add-Content $MainLogFile '[Warning] Review users Firstname and Lastname.'
                      # Jumping to the top of the innermost loop
                      Continue
                    }

                    # define parameters
                    $NewUserParams = [ordered]@{FirstName       = $FirstName
                                                LastName        = $LastName
                                                Name            = $LastName + ' ' + $FirstName
                                                ParentContainer = $oun
                                                SamAccountName  = $SamAccountName
						UserPassword    = '**************'
	                  } # end NewUserParams
                    Write-Verbose "Account will be created in $oun"
					          #TODO: Add what happens if person assigned to a non-standard OU
					          if ($starter.ou_path -like '*Non Directorate*')
                    {
					            Write-Verbose 'Non Directorate OU'
						          $exchPolicy = 'edsva-MsExch-ApplyEmailAddressPolicy'
                      $sbNewUser = {
                        New-QADUser @NewUserParams -ObjectAttributes `
                        @{edsaCreateMSExchMailbox='true';mailNickname="$starter.FirstName"+'.'+"$starter.Lastname";homeMDB='CN=****, CN=Databases, CN=Exchange Administrative Group (FYDIBOHF23SPDLT), CN=Administrative Groups, CN=********, CN=Microsoft Exchange, CN=Services, CN=Configuration, DC=SomeDomainName, DC=com';$exchPolicy='TRUE';info = "$file"} -ErrorAction Stop -verbose:$false
						          } # end $sbNewUser
					          }
					
                    else
					          {
						          $sbNewUser = {
                        New-QADUser @NewUserParams `
						            -ObjectAttributes @{edsaCreateMSExchMailbox = 'true'; mailNickname = "$starter.FirstName" + '.' + "$starter.Lastname";info = "$file"} -ErrorAction Stop -Verbose:$false
						          } # end $sbNewUser
					          }
					
					          try
					          {
						          Write-Verbose 'Creating new account'
						          Add-Content $MainLogFile 'Creating new account'
						
						          $User = $sbNewUser.Invoke()
						
						          Write-Verbose 'New account created'
                      Add-Content $MainLogFile 'New account created'
                      $total = $total + 1
						          # Add-Content $MainLogFile $total
                      start-sleep -Seconds 1
						
						          Write-Verbose 'Setting additional parameters'
						          Add-Content $MainLogFile 'Setting additional parameters'
						          Set-QADUser -Identity $User.LogonName -UserMustChangePassword $true -UserPrincipalName "$($User.LogonName)@SomeDomainName.com" `
									          -ObjectAttributes @{
							                employeeID = "$($starter.PersonID)"; `
							                extensionAttribute10 = $Starter.CostCentre; `
							                extensionAttribute11 = $starter.Division; `
							                extensionAttribute12 = $starter.Directorate; `
							                extensionAttribute13 = $starter.Speciality; `
							                extensionAttribute14 = $starter.Department; `
							                extensionAttribute15 = $starter.ManagerPersonID
						                } -ErrorAction Stop -Verbose:$false | Out-Null
						
						          # if IsEmployee, IsHRSS, IsManager or IsElevated = 1
						          if ($starter.IsEmployee -eq 1)
						          {
							          Add-QADGroupMembership -User $User.LogonName -ADGroup 'ADGroupName1'
							          Write-Verbose 'Added to ADGroupName1'
							          Add-Content $MainLogFile 'Added to ADGroupName1'
						          }
						          if ($starter.IsHRSS -eq 1)
						          {
							          Add-QADGroupMembership -User $User.LogonName -ADGroup 'ADGroupName2'
							          Write-Verbose 'Added to ADGroupName2'
							          Add-Content $MainLogFile 'Added to ADGroupName2'
						          }
						          if ($starter.IsManager -eq 1)
						          {
							          Add-QADGroupMembership -User $User.LogonName -ADGroup 'ADGroupName3'
							          Write-Verbose 'Added to ADGroupName3'
							          Add-Content $MainLogFile 'Added to ADGroupName3'
						          }
						          if ($starter.IsElevated -eq 1)
						          {
							          Add-QADGroupMembership -User $User.LogonName -ADGroup 'ADGroupName4'
							          Write-Verbose 'Added to ADGroupName4'
							          Add-Content $MainLogFile 'Added to ADGroupName4'
						          }
						          #TODO: Add account validation function
						
						          # Format output
						          $props = [ordered]@{
							          'PersonID' = $starter.PersonID
							          'FirstName' = $starter.FirstName
							          'LastName' = $starter.LastName
							          'LoginID' = $User.LogonName
							          'Password' = 'NewPassword1'
							          'OfficeEMailAddress' = $User.email
							          'ManagerName' = $starter.ManagerName
							          # Added 23.01.2015 Kapil asked to add these 2 properties                    
							          'ManagerEmail' = $starter.ManagerEMail
							          'ManagerPersonID' = $starter.ManagerPersonID
						          } # end props
						          # Attachment for Service-Now
                      new-object PSObject -Property $props | export-csv $MainPath\$StartersLogsPath\NewAccounts\New_Accounts_$(Split-Path $file -Leaf) -Append -NoTypeInformation
						        } #end try
					          catch
					          {
						          Add-Content $MainLogFile "$($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
						          Write-Warning "$($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
						          #TODO: Decide if we exit the script or go to the next person
					          } #end catch
					 } # end else creating new account
        } # end if EnoughDetails
			
			  Add-Content $MainLogFile '-------------------------'
        Write-Verbose '-------------------------'
			
		  } #end foreach starter
		  # if (test-path "$MainPath\$StartersLogsPath" + \NewAccounts\New_Accounts_$(Split-Path $file -Leaf))
      if (test-path "$MainPath\$StartersLogsPath\NewAccounts\New_Accounts_$file")
		  {
			  #TODO: Email formatting
			  Send-MailMessage -to 'SomeEmail@doesnotexist.com' -from 'SomeEmail@doesnotexist.com' -Body 'New accounts created, see attachment' -Subject "New accounts $file" -SmtpServer 'relay.gstt.nhs.uk' -Attachments "$MainPath\$StartersLogsPath\NewAccounts\New_Accounts_$file"
			} #end if 
		
		# Move file to archive folder
		Move-Item -Path $($MainPath + '\' + $ArchivePath + '\' + $file) -Destination $($MainProps.MainPath + '\' + $MainProps.StartersLogsPath)
    
	} # end foreach file 
  Add-Content $TmpFile "Total new accounts created: $total"
} # end function New-GSTTADAccount

function Add-QADGroupMembership
{
	[CmdletBinding(SupportsShouldProcess)]
	Param
	(
		[Parameter(Mandatory)]
		[string]$User,
		[Parameter(Mandatory)]
		[string]$ADGroup
	)
	
	try
	{
		Add-QADGroupMember $ADGroup -Member $User -ErrorAction Stop
	}
	catch
	{
		Add-Content $TmpFile "$($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
		Write-Warning "$($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
	} #end try/catch
	
} # end function Add-ADGroupMembership

function Test-SamAccountName
{
  <#
    .DESCRIPTION
    We just need to check if login already exists in AD
    .OUTPUT
    Boolean :
      $false - login not in AD
      $true  - login found in AD 
  #>
  Param ($SamAccountName)
  $loginname = Get-QADUser -SamAccountName $SamAccountName | Select-Object SamAccountName
  if ($loginname -eq $null)
  {
    write-output $false
  }
  else
  {
    write-output $true
  }
} # end function Test-SamAccountName

# ****** ENTRY POINT ***********
#region Setup environment
# 01 - Setup variables
$timestamp = Get-Date -Format dd_MM_yyyy_HH_mm
$MainPath = "SomePath\User Prov And Change RPT"
$ArchivePath = 'AD\Archive'
$StartersLogsPath = 'PowerShell Logs\Archive\Starters'
# $script:total = 0 # just to keep a count of how many new accounts we created
$NewFiles = @()
$script:TmpFile = [Io.Path]::GetTempFileName()

$startTime = $endTime = $null
$error.Clear()

$startTime = (Get-date).ToString()

$MainProps = @{
	'MainPath' = $MainPath
	'MainPathTest' = $MainPathTest
	'ArchivePath' = $ArchivePath
	'StartersLogsPath' = $StartersLogsPath
	'Timestamp' = $timestamp
}

$to = 'SomeEmailAddress@email.com'
$from = 'UserProvisioning@email.com'
$subject = 'ESR starters script'
$SMTPServer = 'SMTPServer'

$EmailSettings = @{
	'To' = $to
	'From' = $from
	'Subject' = $subject
	'SMTPServer' = $SMTPServer
}
#endregion

#region 02 - Check paths
$access = Test-AccessToPathsAndFiles -MainProps $MainProps -Verbose
if (-not $access)
{
    Add-Content $TmpFile 'One of the required paths are missing, the script will exit.'
    # Send email to notify
    
    if ($error[0])
    {
        Write-Warning $error[0].Exception.Message
        $body=$error[0].Exception.Message
        $body += '. Check access to production and logging folders!'
    }
    else 
    {
        $body = 'One of the required paths are missing, the script will exit.'
    }
    # We can only move logfile to logs folder if we have access to it
    if ($body -notlike '*Access is denied*')
    {
        try
        {
            Move-Item -Path $TmpFile -Destination "$MainPath\$StartersLogsPath\$timestamp.log" -ErrorAction Stop
        }
        catch 
        {
            $body += '. Logfile with this timestamp already exists!'
        }
    }
    
    Send-MailMessage @EmailSettings -Body $body

    Exit
} # end if no access to files
#endregion

#region 03 - Load Quest ActiveRoles ADManagement PSSnapin
Try
{
	Add-PSSnapin Quest.ActiveRoles.ADManagement -ErrorAction 'Stop'
	Connect-QADService -Service 'ARSServer' -Proxy | out-null
}
Catch
{
	# $text = Write-warning $_.Exception.Message
	Add-Content -Path $TmpFile -value "[Error] $_.Exception.Message"
	Send-MailMessage @EmailSettings -Body $_.Exception.Message
	Move-Item -Path $TmpFile -Destination "$MainPath\$StartersLogsPath\$timestamp.log"
	Exit
}
#endregion

#region 04 - Main log file

if (-not (Test-Path "$MainPath\$StartersLogsPath\starters_$timestamp.log"))
{
	$script:MainLogFile = New-Item $MainPath\$StartersLogsPath\starters_$timestamp.log -ItemType file
}
else
{
	$script:MainLogFile = "$MainPath\$StartersLogsPath\starters_$timestamp.log"
}
if ($MainLogFile)
{
	Write-Verbose "Logfile: $(split-Path $MainLogFile -leaf)"
	Add-Content $TmpFile "Logfile: $(split-Path $MainLogFile -leaf)"
	Add-Content $MainLogFile $(Get-Date)
}
else
{
	Write-Warning '[Error] Could not create or open log file. Script will stop!'
	Add-Content $TmpFile "Could not create or open log file $MainLogFile"
	$body = "Could not create or open log file $MainLogFile"
	Send-MailMessage @EmailSettings -Body $body
	Move-Item -Path $TmpFile -Destination "$MainPath\$StartersLogsPath\$timestamp.log"
	Exit
}
#endregion

#region 05 - Finding new files
$StartersNewFiles = Get-ChildItem $($MainProps.MainPath + '\' + $MainProps.ArchivePath) -Filter 'Starters*'
if ($StartersNewFiles -eq $null)
{
    Write-Warning '[Warning] No new starters files to process. Script will stop!'
    Add-Content $TmpFile '[Warning] No new starters files to process. Script will stop!'
    $body = 'No new starters files to process.'
    Send-MailMessage @EmailSettings -Body $body
    Move-Item -Path $TmpFile -Destination "$MainPath\$StartersLogsPath\$timestamp.log"
    Exit
}
else
{
    foreach ($StartersNewFile in $StartersNewFiles)
    {
        $rows = $null
        $rows = import-csv $($MainPath + '\' + $ArchivePath + '\' + $StartersNewFile.Name) | where-object { $_ }
        if ($rows)
        {
            $NewFiles += $StartersNewFile.Name
        }
        else
        {
            Add-Content $MainLogFile "[Warning] $($StartersNewFile.Name) is empty"
            Add-Content $TmpFile "$($StartersNewFile.Name) is empty"
            Move-Item -Path $($MainPath + '\' + $ArchivePath + '\' + $StartersNewFile.Name) -Destination $($MainProps.MainPath + '\' + $MainProps.StartersLogsPath)
        }
    }
}
#endregion

#$NewFiles = Get-ChildItem $($MainProps.MainPath + '\' + $MainProps.ArchivePath) -Filter 'Starters*'

#region 06 - Create new accounts
if ($NewFiles)
{
    New-GSTTADAccount -MainProps $MainProps -StarterFiles $NewFiles -Verbose
}
else
{
    Add-Content $MainLogFile '[Warning] No new files to process'
    Add-Content $TmpFile 'No new files to process'
}
#endregion

#region 07 - Adding to groups

#endregion

#region 08 - finalize logging
$endTime = (Get-date).ToString()
$logResults = @"
** Total script time was $((New-TimeSpan -Start $startTime -End $endTime).TotalSeconds) seconds
** Total errors: $($error.count)
"@

Add-Content $MainLogFile $logResults
Add-Content $TmpFile $logResults

foreach ($e in $error)
{
  Add-Content $MainLogFile $e
	Add-Content $TmpFile $e
}

$body = Get-Content $TmpFile
$bodytext = $null
foreach ($line in $body)
{
    $bodytext += "$line <br>"
}
# $bodytext += "Total new accounts created: $total"
#TODO: Sort out email formatting
Send-MailMessage @EmailSettings -BodyAsHtml $bodytext
Write-Host $TmpFile
Write-Host "$MainPath\$StartersLogsPath\$timestamp.log"
Move-Item -Path $TmpFile -Destination "$MainPath\$StartersLogsPath\$timestamp.log"
#endregion
