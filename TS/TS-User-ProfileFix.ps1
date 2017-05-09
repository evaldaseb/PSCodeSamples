Function Set-Owner {
    [cmdletbinding(
        SupportsShouldProcess = $True
    )]
    Param (
        [parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$CommunityUser,
        [parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Path,
        [parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Account,
        [parameter()]
        [switch]$Recurse
    )
    Begin {
        #Prevent Confirmation on each Write-Debug command when using -Debug
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }
        Try {
            [void][TokenAdjuster]
        } Catch {
            $AdjustTokenPrivileges = @"
            using System;
            using System.Runtime.InteropServices;

             public class TokenAdjuster
             {
              [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
              internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
              ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
              [DllImport("kernel32.dll", ExactSpelling = true)]
              internal static extern IntPtr GetCurrentProcess();
              [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
              internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr
              phtok);
              [DllImport("advapi32.dll", SetLastError = true)]
              internal static extern bool LookupPrivilegeValue(string host, string name,
              ref long pluid);
              [StructLayout(LayoutKind.Sequential, Pack = 1)]
              internal struct TokPriv1Luid
              {
               public int Count;
               public long Luid;
               public int Attr;
              }
              internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
              internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
              internal const int TOKEN_QUERY = 0x00000008;
              internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
              public static bool AddPrivilege(string privilege)
              {
               try
               {
                bool retVal;
                TokPriv1Luid tp;
                IntPtr hproc = GetCurrentProcess();
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
                tp.Count = 1;
                tp.Luid = 0;
                tp.Attr = SE_PRIVILEGE_ENABLED;
                retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
                retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                return retVal;
               }
               catch (Exception ex)
               {
                throw ex;
               }
              }
              public static bool RemovePrivilege(string privilege)
              {
               try
               {
                bool retVal;
                TokPriv1Luid tp;
                IntPtr hproc = GetCurrentProcess();
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
                tp.Count = 1;
                tp.Luid = 0;
                tp.Attr = SE_PRIVILEGE_DISABLED;
                retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
                retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                return retVal;
               }
               catch (Exception ex)
               {
                throw ex;
               }
              }
             }
"@
            Add-Type $AdjustTokenPrivileges
        }

        #Activate necessary admin privileges to make changes without NTFS perms
        [void][TokenAdjuster]::AddPrivilege("SeRestorePrivilege") #Necessary to set Owner Permissions
        [void][TokenAdjuster]::AddPrivilege("SeBackupPrivilege") #Necessary to bypass Traverse Checking
        [void][TokenAdjuster]::AddPrivilege("SeTakeOwnershipPrivilege") #Necessary to override FilePermissions
    }
    Process {
        ForEach ($Item in $Path) {
            Write-Verbose "FullName: $Item"
            #The ACL objects do not like being used more than once, so re-create them on the Process block
            $DirOwner = New-Object System.Security.AccessControl.DirectorySecurity
            $DirOwner.SetOwner([System.Security.Principal.NTAccount]$Account)
            $FileOwner = New-Object System.Security.AccessControl.FileSecurity
            $FileOwner.SetOwner([System.Security.Principal.NTAccount]$Account)
            $DirAdminAcl = New-Object System.Security.AccessControl.DirectorySecurity
            $FileAdminAcl = New-Object System.Security.AccessControl.DirectorySecurity
            $AdminACL = New-Object System.Security.AccessControl.FileSystemAccessRule('Builtin\Administrators','FullControl','ContainerInherit,ObjectInherit','InheritOnly','Allow')
            $FileAdminAcl.AddAccessRule($AdminACL)
            $DirAdminAcl.AddAccessRule($AdminACL)
            Try {
                $Item = Get-Item -LiteralPath $Item -Force -ErrorAction Stop
                If (-NOT $Item.PSIsContainer) {
                    If ($PSCmdlet.ShouldProcess($Item, 'Set File Owner')) {
                        Try {
                            $Item.SetAccessControl($FileOwner)
                        } Catch {
                            Write-Warning "Couldn't take ownership of $($Item.FullName)! Taking FullControl of $($Item.Directory.FullName)"
                            $Item.Directory.SetAccessControl($FileAdminAcl)
                            $Item.SetAccessControl($FileOwner)
                        }
                    }
                } Else {
                    If ($PSCmdlet.ShouldProcess($Item, 'Set Directory Owner')) {                        
                        Try {
                            $Item.SetAccessControl($DirOwner)
                        } Catch {
                            Write-Warning "Couldn't take ownership of $($Item.FullName)! Taking FullControl of $($Item.Parent.FullName)"
                            $Item.Parent.SetAccessControl($DirAdminAcl) 
                            $Item.SetAccessControl($DirOwner)
                        }
                    }
                    If ($Recurse) {
                        [void]$PSBoundParameters.Remove('Path')
                        Get-ChildItem $Item -Force | Set-Owner @PSBoundParameters
                    }
                }
            } Catch {
                Write-Warning "$($Item): $($_.Exception.Message)"
            }
        }
    }
    End {  
        #Remove priviledges that had been granted
        [void][TokenAdjuster]::RemovePrivilege("SeRestorePrivilege") 
        [void][TokenAdjuster]::RemovePrivilege("SeBackupPrivilege") 
        [void][TokenAdjuster]::RemovePrivilege("SeTakeOwnershipPrivilege")     
    }
}

function Grant-userFullRights {            
    [cmdletbinding()]            
    param(            
        [parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$CommunityUser,
        [parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Account,
        [parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Path,
        [parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [switch]$Set       
    )
    
    $rule=new-object System.Security.AccessControl.FileSystemAccessRule ($Account,"FullControl","Allow")
    $acl = Get-Acl $path
    if ($set) {
        $acl.SetAccessRule($rule) 
        try {
            Write-Verbose "[TRY] Checking for granting FullControl"
            Set-ACL -Path $Path -ACLObject $acl -ErrorAction Stop
            Write-Verbose "[TRY] No issues found"
            $grant_ok = $true
            Write-Verbose $grant_ok
        }
        catch {
            $grant_ok = $false
        } #end TryCatch
    }
    else {
        $acl.RemoveAccessRule($rule) 
        Set-ACL -Path $Path -ACLObject $acl
    }
    Write-Output $grant_ok
} #end function Grant-userFullRights

function Remove-HPRegKeys {
    [cmdletbinding()]            
    param(
        [parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$PathNTUSERDAT,
        [parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$CommunityUser,
        [parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$ActivitySummaryLog
    )

    Write-Verbose "Loading hive reg.exe"
    Add-Content $ActivitySummaryLog "Loading hive reg.exe"

    $ReturnCode = c:\windows\system32\reg.exe load HKLM\$CommunityUser $PathNTUSERDAT

    if ($ReturnCode -like '*The operation completed successfully*') {
        Write-Verbose "Successfully loaded hive"
        Add-Content $ActivitySummaryLog "Successfully loaded hive"

        $HiveLoad_ok = $true

        if (test-path "HKLM:\$CommunityUser\Software\Hewlett-Packard") {
            Write-Verbose "Found Hewlett-Packard keys, deleting"
            Add-Content $ActivitySummaryLog "Found Hewlett-Packard keys, deleting"
            
            try {
                Write-Verbose "[TRY] Deleting Hewlett-Packard keys"
                Remove-Item "HKLM:\$CommunityUser\Software\Hewlett-Packard" -Recurse -Confirm:$false -ErrorAction Stop
                Write-Verbose "[TRY] No issues deleting Hewlett-Packard keys"
                Add-Content $ActivitySummaryLog "Successfully deleted Hewlett-Packard keys"
            }
            catch {
                Write-Verbose "[CATCH] Could not delete Hewlett-Packard keys"
                Add-Content $ActivitySummaryLog "Could not delete Hewlett-Packard keys"
            }
        }
        else {
            Write-Verbose "Hewlett-Packard keys not found"
            Add-Content $ActivitySummaryLog "Hewlett-Packard keys not found"
        }
    }
    else {
        Write-Verbose "Could not load hive"
        Add-Content $ActivitySummaryLog "[ERROR] Could not load hive"
    }

    if ($HiveLoad_ok) { 

        Write-host "Unloading $CommunityUser hive ..."
        Add-Content $ActivitySummaryLog "Unloading $CommunityUser hive ..."

        [gc]::collect()

        start-sleep -s 1

        $ReturnCodeUnload = c:\windows\system32\reg.exe unload HKLM\$CommunityUser

        if ($ReturnCodeUnload -like '*The operation completed successfully*') {
            Write-Verbose "Successfully unloaded hive"
            Add-Content $ActivitySummaryLog "Successfully unloaded hive"

        }
        else {
            Write-Warning "Could not unload hive"
            Add-Content $ActivitySummaryLog "[ERROR] Could not unload hive"
        }
    
    } #end if $HiveLoad_ok
      
    Write-Verbose "Running Registry Usage tool"
    Add-Content $ActivitySummaryLog "Running Registry Usage tool"
        
    $ErrorActionPreference = 'SilentlyContinue'
    $ReturnCodeRU = E:\Scripts\CommunityUsersProfileFix\ru.exe -h $PathNTUSERDAT
    $ErrorActionPreference = 'Continue'

    Add-Content $ActivitySummaryLog $ReturnCodeRU
}            

# ***** ENTRY POINT ***********
$Users = Get-Content $PSScriptRoot\Users.txt
$Account = 'svc_sccm'
$VerbosePreference  = [System.Management.Automation.ActionPreference]::Continue
$PathProfile      = "SomeNetworkShare\$CommunityUser\Profile"

foreach ($CommunityUser in $Users) {
    
    $timestamp         = Get-Date -Format dd_MM_yyyy_HH_mm
    $PathProfile       = "SomeNetworkShare\$CommunityUser\Profile"
    $PathNTUSERDAT     = $PathProfile + '\' + 'NTUSER.DAT'
    $PathNTUSERDATLOG  = $PathProfile + '\' + 'NTUSER.DAT.LOG'
    $PathNTUSERDATLOG1 = $PathProfile + '\' + 'NTUSER.DAT.LOG1'
    $PathNTUSERDATLOG2 = $PathProfile + '\' + 'NTUSER.DAT.LOG2'
    $PathNTUSERDATLOG3 = $PathProfile + '\' + 'NTUSER.DAT.LOG3'
    $PathNTUSERDATLOG4 = $PathProfile + '\' + 'NTUSER.DAT.LOG4'

    if (-not (test-path SomeNetworkShare\ActivitySummaryLog_$CommunityUser.log) ) {
        $ActivitySummaryLog = new-item "SomeNetworkShare\ActivitySummaryLog_$CommunityUser.log" -ItemType file
    }
    else {
        $ActivitySummaryLog = "SomeNetworkShare\ActivitySummaryLog_$CommunityUser.log"
    }

    if (-not (test-path SomeNetworkShare\ErrorDetailLog_$CommunityUser.log) ) {
        $ErrorDetailLog = new-item "SomeNetworkShare\ErrorDetailLog_$CommunityUser.log" -ItemType file
    }
    else {
        $ErrorDetailLog = "SomeNetworkShare\ErrorDetailLog_$CommunityUser.log"
    }

    Add-Content $ActivitySummaryLog $timestamp

    if (test-path $PathProfile) {
        Write-Verbose "Taking ownership of $PathProfile"
        Add-Content $ActivitySummaryLog "Taking ownership of $PathProfile"
        Set-Owner -CommunityUser $CommunityUser -Account $Account -Path $PathProfile
    }
    else {
        Add-Content $ActivitySummaryLog "[WARNING] path $PathProfile not found!"
        Continue
    }

    # Check if ownership has been taken
    try {
        Write-Verbose 'Checking for Folder Owner'
        $FolderOwner = get-acl -Path $PathProfile -ErrorAction Stop 
        $owner_ok = $true
        Write-Verbose '[TRY] No issues found'
    }
    catch {
        $owner_ok = $false
        Add-Content $ActivitySummaryLog "[ERROR]   $_.InvocationInfo.ScriptLineNumber"
        Add-Content $ErrorDetailLog $PathProfile
        Add-Content $ErrorDetailLog $_.Exception.Message
    } #end TryCatch

    if ($owner_ok -eq $false) {break}

    Write-Verbose 'Successfully took ownership'
    Write-Verbose "Granting FullControl to $PathProfile"
    Add-Content $ActivitySummaryLog 'Successfully took ownership'
    Add-Content $ActivitySummaryLog "Granting FullControl to $PathProfile"

    $FullControl = Grant-userFullRights -CommunityUser $CommunityUser -Account $Account -Path $PathProfile -Set

    if ($FullControl) {
        Add-Content $ActivitySummaryLog "Successfully granted FullControl to $PathProfile"
        Add-Content $ActivitySummaryLog "Taking ownership of $PathNTUSERDAT"
        Write-Verbose "Taking ownership of $PathNTUSERDAT"
    
        if (test-path $PathNTUSERDAT) {
    
            Set-Owner -CommunityUser $CommunityUser -Account $Account -Path $PathNTUSERDAT
    
            # Check if ownership has been taken
            try {
                Write-Verbose "[TRY] Checking for $PathNTUSERDAT Owner"
                $FileOwner = get-acl -Path $PathNTUSERDAT -ErrorAction Stop 
                $owner_ok = $true
                Write-Verbose '[TRY] No issues found'
                Add-Content $ActivitySummaryLog 'Successfully took ownership'
            }
            catch {
                $owner_ok = $false
                Add-Content $ActivitySummaryLog '[ERROR] Error found when trying to take ownership of $PathNTUSERDAT'
                Add-Content $ActivitySummaryLog '[ERROR] Check ErrorDetailLog.log file'
                Add-Content $ActivitySummaryLog '------------------------------'
                Add-Content $ErrorDetailLog $PathNTUSERDAT
                Add-Content $ErrorDetailLog "Script Line number : $($_.InvocationInfo.ScriptLineNumber)"
                Add-Content $ErrorDetailLog $_.Exception.Message
                Add-Content $ErrorDetailLog $_.InvocationInfo.Line
                Add-Content $ErrorDetailLog '------------------------------'
            } #end TryCatch
    
            Add-Content $ActivitySummaryLog "Taking ownership of $PathNTUSERDATLOG"
            Write-Verbose "Taking ownership of $PathNTUSERDATLOG"
            Set-Owner -CommunityUser $CommunityUser -Account $Account -Path $PathNTUSERDATLOG
        
            if (Test-Path $PathNTUSERDATLOG1) {
                Set-Owner -CommunityUser $CommunityUser -Account $Account -Path $PathNTUSERDATLOG1
            }
        
            if (Test-Path $PathNTUSERDATLOG2) {
                Set-Owner -CommunityUser $CommunityUser -Account $Account -Path $PathNTUSERDATLOG2
            }

            if (Test-Path $PathNTUSERDATLOG3) {
                Set-Owner -CommunityUser $CommunityUser -Account $Account -Path $PathNTUSERDATLOG3
            }

            if (Test-Path $PathNTUSERDATLOG4) {
                Set-Owner -CommunityUser $CommunityUser -Account $Account -Path $PathNTUSERDATLOG4
            }
    
            try {
                    Write-Verbose "[TRY] Checking for $PathNTUSERDATLOG Owner"
                    $FileOwner = get-acl -Path $PathNTUSERDATLOG -ErrorAction Stop 
                    $owner_ok = $true
                    Write-Verbose '[TRY] No issues found'
                    Add-Content $ActivitySummaryLog 'Successfully took ownership'
            }
            catch {
                $owner_ok = $false
                Add-Content $ActivitySummaryLog "[ERROR] Error found when trying to take ownership of $PathNTUSERDATLOG"
                Add-Content $ActivitySummaryLog '[ERROR] Check ErrorDetailLog.log file'
                Add-Content $ActivitySummaryLog '------------------------------'
                Add-Content $ErrorDetailLog $PathNTUSERDATLOG
                Add-Content $ErrorDetailLog "Script Line number : $($_.InvocationInfo.ScriptLineNumber)"
                Add-Content $ErrorDetailLog $_.Exception.Message
                Add-Content $ErrorDetailLog $_.InvocationInfo.Line
                Add-Content $ErrorDetailLog '------------------------------'
            } #end TryCatch

            Write-Verbose "Granting FullControl to $PathNTUSERDAT"
            Add-Content $ActivitySummaryLog "Granting FullControl to $PathNTUSERDAT"

            $FullControlNTUSERDAT = Grant-userFullRights -CommunityUser $CommunityUser -Account $Account -Path $PathNTUSERDAT -Set

            Write-Verbose "Granting FullControl to $PathNTUSERDATLOG"
            Add-Content $ActivitySummaryLog "Granting FullControl to $PathNTUSERDATLOG"

            $FullControlNTUSERDATLOG = Grant-userFullRights -CommunityUser $CommunityUser -Account $Account -Path $PathNTUSERDATLOG -Set
        
            if (test-path $PathNTUSERDATLOG1) {
                $FullControlNTUSERDATLOG1 = Grant-userFullRights -CommunityUser $CommunityUser -Account $Account -Path $PathNTUSERDATLOG1 -Set
            }
        
            if (test-path $PathNTUSERDATLOG2) {
                $FullControlNTUSERDATLOG2 = Grant-userFullRights -CommunityUser $CommunityUser -Account $Account -Path $PathNTUSERDATLOG2 -Set
            }

            if (test-path $PathNTUSERDATLOG3) {
                $FullControlNTUSERDATLOG3 = Grant-userFullRights -CommunityUser $CommunityUser -Account $Account -Path $PathNTUSERDATLOG3 -Set
            }

            if (test-path $PathNTUSERDATLOG4) {
                $FullControlNTUSERDATLOG4 = Grant-userFullRights -CommunityUser $CommunityUser -Account $Account -Path $PathNTUSERDATLOG4 -Set
            }

            if ($FullControlNTUSERDAT -and $FullControlNTUSERDATLOG) {
                Write-Verbose "Successfully granted FullControl to NTUSER.DAT and NTUSER.DAT.LOG"
                Add-Content $ActivitySummaryLog "Successfully granted FullControl to NTUSER.DAT and NTUSER.DAT.LOG"
    
                Write-Verbose "Fixing NTUSER.DAT ..."
                Add-Content $ActivitySummaryLog "Fixing NTUSER.DAT ..."
    
                $NTUserDatFile = gci $PathNTUSERDAT -Hidden | select Length
                $NTUserDatFileBefore = [math]::Round($NTUserDatFile.Length/1MB,2)

                Remove-HPRegKeys -PathNTUSERDAT $PathNTUSERDAT -CommunityUser $CommunityUser -ActivitySummaryLog $ActivitySummaryLog

                $NTUserDatFile = gci $PathNTUSERDAT -Hidden | select Length
                $NTUserDatFileAfter = [math]::Round($NTUserDatFile.Length/1MB,2)

                Write-Verbose "NTUSER.DAT was: $NTUserDatFileBefore MB"
                Add-Content $ActivitySummaryLog "NTUSER.DAT was: $NTUserDatFileBefore MB"

                Write-Verbose "NTUSER.DAT now: $NTUserDatFileAfter MB"
                Add-Content $ActivitySummaryLog "NTUSER.DAT now: $NTUserDatFileAfter MB"
            }
            else {
                Write-Verbose "Could not grant FullControl to NTUSER.DAT and NTUSER.DAT.LOG"
                Add-Content $ActivitySummaryLog "[WARNING] Could not grant FullControl to NTUSER.DAT and NTUSER.DAT.LOG"
            } #end IfElse $FullControlNTUSERDAT -and $FullControlNTUSERDATLOG

        
        } #end if test-path $PathNTUSERDAT

        else {
            Write-Verbose "$PathNTUSERDAT not found"
            Add-Content $ActivitySummaryLog "[WARNING] $PathNTUSERDAT not found"
        }

    } #end if $FullControl           
    else {
        Add-Content $ActivitySummaryLog "[WARNING]   Could not grant FullControl to $PathProfile"
    } #end else $FullControl

    Write-Verbose "Restoring ownership and permissions"
    Add-Content $ActivitySummaryLog "Restoring ownership and permissions"

    Grant-userFullRights -CommunityUser $CommunityUser -Account $Account -Path $PathNTUSERDAT

    Grant-userFullRights -CommunityUser $CommunityUser -Account $Account -Path $PathNTUSERDATLOG

    if (Test-Path $PathNTUSERDATLOG1) {
        Grant-userFullRights -CommunityUser $CommunityUser -Account $Account -Path $PathNTUSERDATLOG1
    }

    if (Test-Path $PathNTUSERDATLOG2) {
        Grant-userFullRights -CommunityUser $CommunityUser -Account $Account -Path $PathNTUSERDATLOG2
    }

    if (Test-Path $PathNTUSERDATLOG3) {
        Grant-userFullRights -CommunityUser $CommunityUser -Account $Account -Path $PathNTUSERDATLOG3
    }

    if (Test-Path $PathNTUSERDATLOG4) {
        Grant-userFullRights -CommunityUser $CommunityUser -Account $Account -Path $PathNTUSERDATLOG4
    }


    Set-Owner -CommunityUser $CommunityUser -Account $CommunityUser -Path $PathNTUSERDAT
    Set-Owner -CommunityUser $CommunityUser -Account $CommunityUser -Path $PathNTUSERDATLOG

    if (Test-Path $PathNTUSERDATLOG1) {
        Set-Owner -CommunityUser $CommunityUser -Account $CommunityUser -Path $PathNTUSERDATLOG1
    }
        
    if (Test-Path $PathNTUSERDATLOG2) {
        Set-Owner -CommunityUser $CommunityUser -Account $CommunityUser -Path $PathNTUSERDATLOG2
    }

    if (Test-Path $PathNTUSERDATLOG3) {
        Set-Owner -CommunityUser $CommunityUser -Account $CommunityUser -Path $PathNTUSERDATLOG3
    }

    if (Test-Path $PathNTUSERDATLOG4) {
        Set-Owner -CommunityUser $CommunityUser -Account $CommunityUser -Path $PathNTUSERDATLOG4
    }
    
    Grant-userFullRights -CommunityUser $CommunityUser -Account $Account -Path $PathProfile

    Set-Owner -CommunityUser $CommunityUser -Account $CommunityUser -Path $PathProfile

    Write-Verbose "All tasks completed"
    Add-Content $ActivitySummaryLog "All tasks completed"

    Add-Content $ActivitySummaryLog "------------------------------------"
    
} #end foreach User
