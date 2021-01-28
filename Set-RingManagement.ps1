<#
.SYNOPSIS

.DESCRIPTION

.NOTES
  Version:        1.0
  Author:         Morten Rønborg (mr@zwable.com)
  Creation Date:  02-12-2020
  Purpose/Change: 28-01-2021
#>

#Variables
#Early Adopters
[string]$EarlyAdoptersUserGroupName = "Sec-MEM-EarlyAdopters-Users"  # Supports nested groups (excluding device objects)
[string]$EarlyAdoptersDeviceGroupName = "Sec-MEM-EarlyAdopters-Devices" # Supports nested groups (excluding user objects)
[string]$PrefixGroupEarlyAdopters = "Sec-AutoRunbook-MEMEarlyAdopters-" # Prefix of ring groups
[int]$NumberOfGroupsEarlyAdopters = 2 # Number of groups in this ring which devices will be spread equally on

#Early verification
[string]$EarlyVerificationUserGroupName = "Sec-MEM-EarlyVerification-Users" # Supports nested groups (excluding device objects)
[string]$EarlyVerificationDeviceGroupName = "Sec-MEM-EarlyVerification-Devices" # Supports nested groups (excluding user objects)
[string]$PrefixGroupEarlyVerification = "Sec-AutoRunbook-MEMEarlyVerification-"
[int]$NumberOfGroupsEarlyVerification = 4 # Number of groups in this ring which devices will be spread equally on

#Early production
[string]$EarlyProductionUserGroupName = "Sec-MEM-EarlyProduction-Users" # Supports nested groups (excluding device objects)
[string]$EarlyProductionDeviceGroupName = "Sec-MEM-EarlyProduction-Devices" # Supports nested groups (excluding user objects)
[string]$PrefixGroupEarlyProduction = "Sec-AutoRunbook-MEMEarlyProduction-"
[int]$NumberOfGroupsEarlyProduction = 8 # Number of groups in this ring which devices will be spread equally on

#Global production
[string]$GlobalProductionDeviceGroupName = "Sec-MEM-GlobalProduction-Devices" # Supports nested groups (excluding user objects)
[string]$PrefixGroupGlobalProduction = "Sec-AutoRunbook-MEMGlobalProduction-"
[int]$NumberOfGroupsGlobalProduction = 16 # Number of groups in this ring which devices will be spread equally on

#Global excluded devices
[string]$GroupExcludedDevicesName = "Sec-AutoRunbook-MEMDeviceRingsExcluded" # Supports nested groups (excluding user objects)

#Start
$StartTime = Get-Date

################################
#Variable end
################################
try {

    #Import modules
    Import-Module -Name AzureAD -ErrorAction Stop

}
catch {

    #Exit if not able to import modules
    Throw "ERROR: AzureAD and Microsoft.Graph.Intune PowerShell module not installed $_"
}

#Define credentials object
$Credential = Get-AutomationPSCredential -Name IntuneAutomation

#Connect graph
try {

    Connect-AzureAD -Credential $Credential
}
catch {
  
    #Exit if not able to import modules
    Throw "ERROR: Error connecting to graph and azure $_"
}

#region begin functions
############### Functions - Start ###############
function Split-Array{
    param (
        [array]$InArray,
        [int]$Parts,
        [int]$Size
    )
  
      #In case the objects are less than the parts
      If($InArray.Count -le $Parts){
  
          $Parts = $InArray.Count
      }
  
      #Define parts or size
      if($Parts){
          $PartSize = [Math]::Ceiling($InArray.Count / $Parts)
      }
      if($Size){
          $PartSize = $Size
          $Parts = [Math]::Ceiling($InArray.Count / $Size)
      }
  
      #Define list object array
      $OutArray = New-Object 'System.Collections.Generic.List[psobject]'
  
      #Run through all parts
      for ($i=1; $i -le $Parts; $i++) {

          #Define start and end index
          $Start = (($i-1)*$PartSize)
          $End = (($i)*$PartSize) - 1
          if($End -ge $InArray.Count){
              $End = $InArray.Count -1
          }
  
          #Add to list object array
          $OutArray.Add(@($InArray[$Start..$End]))
      }
  
      #Return output
      Return ,$OutArray
  }
function Get-AzureADNestedGroupObjects{
    Param
    (
        $GroupObj
    )

    #Get the AD object, and get group membership
    $Members = Get-AzureADGroupMember -ObjectId $GroupObj.ObjectId -All $True

    #Foreach member in the group.
    Foreach($Member in $Members)
    {
        #If the member is a group.
        If($Member.ObjectType -eq "Group")
        {
            #Run the function again against the group
            $Objects += Get-AzureADNestedGroupObjects -GroupObj $Member
        }
        Else
        {

            #Add the object to the object array
            If(!($Member.ObjectId -in $Objects.ObjectId)){

                #Add to the array
                $Objects += @($Member)
            }
        }
    }

    #Return the users (in case users belongs to multiple nested groups, get unique)
    Return ($Objects | Sort-Object -Property ObjectId -Unique)
}

function Get-CreateOrGetAzureADGroup {
    param (
        $DisplayName,
        $Description
    )
 
    #Get group
    $Group = Get-AzureADGroup -Filter "DisplayName eq '$DisplayName'"

    if([string]::IsNullOrEmpty($Group)){

        #Create the group
        Write-Output "[Get-CreateOrGetAzureADGroup]::The group '$DisplayName' does not exist. Creating it..."
        $Group = New-AzureADGroup -DisplayName $DisplayName -Description $Description -MailEnabled $false -SecurityEnabled $true -MailNickName "NotSet"
    }
    
    #Return group
    Return $Group
}

function Set-AllignGroupMemberships {
    param (
        $Group,
        [array]$AADObjectIDs
    )

    #State amount to 
    Write-Output "[Set-AllignGroupMemberships:$($Group.DisplayName)]::Expected objects in group: $($AADObjectIDs.Count)"

    #Get current members of the group
    [array]$CurrentMembersIDs = (Get-AzureADGroupMember -ObjectId $Group.ObjectID -All $True).ObjectId
    Write-Output "[Set-AllignGroupMemberships:$($Group.DisplayName)]::Current objects in group: $($CurrentMembersIDs.Count)"

    #Declare variables
    [array]$ObjectsIDsToRemove = $CurrentMembersIDs | Where-Object{$_ -notin $AADObjectIDs}
    [array]$ObjectsIDsToAdd =  $AADObjectIDs | Where-Object {$_ -notin $CurrentMembersIDs}

    #Write host
    Write-Output "[Set-AllignGroupMemberships:$($Group.DisplayName)]::Objects to add: $($ObjectsIDsToAdd.Count)"
    Write-Output "[Set-AllignGroupMemberships:$($Group.DisplayName)]::Objects to remove: $($ObjectsIDsToRemove.Count)"

    #Removing objects
    Foreach($ObjectID in $ObjectsIDsToRemove){
        
        #Remove member
        Remove-AzureADGroupMember -ObjectID $Group.ObjectID -MemberId $ObjectID
    }

    #Add objects
    Foreach($ObjectID in $ObjectsIDsToAdd){

        #Remove member
        Add-AzureADGroupMember -ObjectID $Group.ObjectID -RefObjectId $ObjectID
    }
}
############### Functions - End ###############
#endregion

#region begin main
############### Main - Start ###############

#Get all current supported PC types
[array]$AllSupportedWinDevices = Get-AzureADDevice -Filter "startswith(DeviceOSType,'Windows')" -All:$True

#Get/Create user groups
$EarlyAdoptersUserGroup = Get-CreateOrGetAzureADGroup -DisplayName $EarlyAdoptersUserGroupName -Description "Do not change the name of this group. This group contains users for Early Adopters."
$EarlyVerificationUserGroup = Get-CreateOrGetAzureADGroup -DisplayName $EarlyVerificationUserGroupName -Description "Do not change the name of this group. This group contains users for Early Verification."
$EarlyProductionUserGroup = Get-CreateOrGetAzureADGroup -DisplayName $EarlyProductionUserGroupName -Description "Do not change the name of this group. This group contains users for Early Production."

#Get/Create device groups
$EarlyAdoptersDeviceGroup = Get-CreateOrGetAzureADGroup -DisplayName $EarlyAdoptersDeviceGroupName -Description "Do not change the name of this group. This group contains devices for Early Adopters."
$EarlyVerificationDeviceGroup = Get-CreateOrGetAzureADGroup -DisplayName $EarlyVerificationDeviceGroupName -Description "Do not change the name of this group. This group contains devices for Early Verification." 
$EarlyProductionDeviceGroup = Get-CreateOrGetAzureADGroup -DisplayName $EarlyProductionDeviceGroupName -Description "Do not change the name of this group. This group contains devices for Early Production."
$GlobalProductionDeviceGroup = Get-CreateOrGetAzureADGroup -DisplayName $GlobalProductionDeviceGroupName -Description "Do not change the name of this group. This group contains devices for Global Production."
$GroupExcludedDevices = Get-CreateOrGetAzureADGroup -DisplayName $GroupExcludedDevicesName -Description "Do not change the name of this group. This group contains devices excluded from the rings. Nested groups are supported. User objects will be ignored."

#Get devices for device groups, we need to exclude these from the global scope as they need to be enforced to each ring later
[array]$EarlyAdoptersGroupDevices = Get-AzureADNestedGroupObjects -GroupObj $EarlyAdoptersDeviceGroup | Where-Object {$_.ObjectType -eq "Device"}
[array]$EarlyVerificationGroupDevices = Get-AzureADNestedGroupObjects -GroupObj $EarlyVerificationDeviceGroup | Where-Object {$_.ObjectType -eq "Device"}
[array]$EarlyProductionGroupDevices = Get-AzureADNestedGroupObjects -GroupObj $EarlyProductionDeviceGroup | Where-Object {$_.ObjectType -eq "Device"}
[array]$GlobalProductionGroupDevices = Get-AzureADNestedGroupObjects -GroupObj $GlobalProductionDeviceGroup | Where-Object {$_.ObjectType -eq "Device"}
[array]$AllExcludedDevices = Get-AzureADNestedGroupObjects -GroupObj $GroupExcludedDevices | Where-Object {$_.ObjectType -eq "Device"}

#Remove the excluded devices from the allsupported win devcices
[array]$AllSupportedWinDevices = $AllSupportedWinDevices | Where-Object {$_.ObjectId -notin $AllExcludedDevices.ObjectId}

#Define all global group
[array]$GlobalWinDevices = $AllSupportedWinDevices | Where-Object {($_.ObjectId -notin $EarlyAdoptersGroupDevices.ObjectId) `
                                                    -and ($_.ObjectId -notin $EarlyVerificationGroupDevices.ObjectId) `
                                                    -and ($_.ObjectId -notin $EarlyProductionGroupDevices.ObjectId) `
                                                    -and ($_.ObjectId -notin $GlobalProductionGroupDevices.ObjectId)}

################################
#Running define device groupings
################################

#Allign EarlyAdopters groups with users devices (Primary Devices in Intune)
[array]$EarlyAdoptersUserGroupMembers = Get-AzureADNestedGroupObjects -GroupObj $EarlyAdoptersUserGroup | Where-Object {$_.ObjectType -eq "User"}
Foreach($User in $EarlyAdoptersUserGroupMembers){

    #Add all users Primary Devices to an array and ensure they are part of the supported device list
    [array]$EarlyAdoptersDevices += (Get-AzureADUserOwnedDevice -ObjectId $User.ObjectId | Where-Object {$_.ObjectId -in $GlobalWinDevices.ObjectId}) 
}

#Allign EarlyVerification groups with users devices (Primary Devices in Intune)
[array]$EarlyVerificationUserGroupMembers = Get-AzureADNestedGroupObjects -GroupObj $EarlyVerificationUserGroup | Where-Object {$_.ObjectType -eq "User"}
Foreach($User in $EarlyVerificationUserGroupMembers){

    #Add all users Primary Devices to an array and ensure they are part of the supported device list (sort out devices from EarlyAdopters as users can be in more groups)
    [array]$EarlyVerificationDevices += (Get-AzureADUserOwnedDevice -ObjectId $User.ObjectId | Where-Object {($_.ObjectId -in $GlobalWinDevices.ObjectId) -and ($_.ObjectId -notin $EarlyAdoptersDevices.ObjectId)})
}

#Allign EarlyVerification groups with users devices (Primary Devices in Intune)
[array]$EarlyProductionUserGroupMembers = Get-AzureADNestedGroupObjects -GroupObj $EarlyProductionUserGroup | Where-Object {$_.ObjectType -eq "User"}
Foreach($User in $EarlyProductionUserGroupMembers){

    #Add all users Primary Devices to an array and ensure they are part of the supported device list (sort out devices from EarlyAdopters and EarlyVerification as users can be in more groups)
    [array]$EarlyProductionDevices += (Get-AzureADUserOwnedDevice -ObjectId $User.ObjectId | Where-Object {($_.ObjectId -in $GlobalWinDevices.ObjectId) -and ($_.ObjectId -notin $EarlyAdoptersDevices.ObjectId) -and ($_.ObjectId -notin $EarlyVerificationDevices.ObjectId)})
}

#Remove all the Primary User based devices from the device pool before defining major groups
[array]$AllSupportedWinDevicesNoPrimaryDevices = $GlobalWinDevices | Where-Object{($_.ObjectId -notin $EarlyAdoptersDevices.ObjectId) `
                                                                                        -and ($_.ObjectId -notin $EarlyVerificationDevices.ObjectId) `
                                                                                        -and ($_.ObjectId -notin $EarlyProductionDevices.ObjectId)} | Sort-Object -Property ObjectId

#Add the amout of devices to each major ring (use unique as one device can have multiple owners)
[array]$AllEarlyAdoptersDevices = ($EarlyAdoptersDevices + $EarlyAdoptersGroupDevices) | Sort-Object -Property ObjectId -Unique
[array]$AllEarlyVerificationDevices = ($EarlyVerificationDevices + $EarlyVerificationGroupDevices) | Where-Object {($_.ObjectId -notin $AllEarlyAdoptersDevices.ObjectId)} | Sort-Object -Property ObjectId -Unique
[array]$AllEarlyProductionDevices = ($EarlyProductionDevices + $EarlyProductionGroupDevices) | Where-Object {($_.ObjectId -notin $AllEarlyAdoptersDevices.ObjectId) -and ($_.ObjectId -notin $AllEarlyVerificationDevices.ObjectId)} | Sort-Object -Property ObjectId -Unique
[array]$AllGlobalProductionDevices = ($AllSupportedWinDevicesNoPrimaryDevices[0..$AllSupportedWinDevicesNoPrimaryDevices.Count] + $GlobalProductionGroupDevices) | Where-Object {($_.ObjectId -notin $AllEarlyAdoptersDevices.ObjectId) -and ($_.ObjectId -notin $AllEarlyVerificationDevices.ObjectId) -and ($_.ObjectId -notin $AllEarlyProductionDevices.ObjectId)} | Sort-Object -Property ObjectId -Unique

Write-Output "[Rings]::Device statistics:`nEarlyAdopters: $($AllEarlyAdoptersDevices.Count) ($($EarlyAdoptersGroupDevices.Count) from $EarlyAdoptersDeviceGroupName)`nEarlyVerification: $($AllEarlyVerificationDevices.Count) ($($EarlyVerificationGroupDevices.Count) from $EarlyVerificationDeviceGroupName)`nEarlyProduction: $($AllEarlyProductionDevices.Count) ($($EarlyProductionGroupDevices.Count) from $EarlyProductionDeviceGroupName)`nGlobalProduction: $($AllGlobalProductionDevices.Count) ($($GlobalProductionGroupDevices.Count) from $GlobalProductionDeviceGroupName)`nTotal excluded devices: $($AllExcludedDevices.Count)`nTotal included devices: $($AllSupportedWinDevices.Count)"

#Split the objects into the count of groups sorting on ObjectId
[array]$EarlyAdoptersGroupings = Split-Array -InArray ($AllEarlyAdoptersDevices | Sort-Object -Property ObjectId) -Parts $NumberOfGroupsEarlyAdopters
[array]$EarlyVerificationGroupings = Split-Array -InArray ($AllEarlyVerificationDevices | Sort-Object -Property ObjectId) -Parts $NumberOfGroupsEarlyVerification
[array]$EarlyProductionGroupings = Split-Array -InArray ($AllEarlyProductionDevices | Sort-Object -Property ObjectId) -Parts $NumberOfGroupsEarlyProduction
[array]$GlobalProductionGroupings = Split-Array -InArray ($AllGlobalProductionDevices | Sort-Object -Property ObjectId) -Parts $NumberOfGroupsGlobalProduction

################################
#Running EarlyAdoption
################################

for ($i = 0; $i -lt $NumberOfGroupsEarlyAdopters; $i++) {
    
    #Define variables
    [array]$GroupMemberIDs = ($EarlyAdoptersGroupings[$i]).ObjectId
    [string]$GroupName = ($PrefixGroupEarlyAdopters + ($i + 1).ToString().PadLeft(4,"0") + "-Devices")
    $Group = Get-CreateOrGetAzureADGroup -DisplayName $GroupName -Description "Do not change the name of this group. This group is maintained by a runbook"

    #Allign memberships
    Write-Output "[EarlyAdoption]::Alligning members of the group '$($Group.DisplayName)' with the ID of '$($Group.ObjectId)'"
    Set-AllignGroupMemberships -Group $Group -AADObjectIDs $GroupMemberIDs
}

################################
#Running EarlyVerification
################################

for ($i = 0; $i -lt $NumberOfGroupsEarlyVerification; $i++) {
    
    #Define variables
    [array]$GroupMemberIDs = ($EarlyVerificationGroupings[$i]).ObjectId
    [string]$GroupName = ($PrefixGroupEarlyVerification + ($i + 1).ToString().PadLeft(4,"0") + "-Devices")
    $Group = Get-CreateOrGetAzureADGroup -DisplayName $GroupName -Description "Do not change the name of this group. This group is maintained by a runbook"

    #Allign memberships
    Write-Output "[EarlyVerification]::Alligning members of the group '$($Group.DisplayName)' with the ID of '$($Group.ObjectId)'"
    Set-AllignGroupMemberships -Group $Group -AADObjectIDs $GroupMemberIDs
}

################################
#Running EarlyProduction
################################

for ($i = 0; $i -lt $NumberOfGroupsEarlyProduction; $i++) {
    
    #Define variables
    [array]$GroupMemberIDs = ($EarlyProductionGroupings[$i]).ObjectId
    [string]$GroupName = ($PrefixGroupEarlyProduction + ($i + 1).ToString().PadLeft(4,"0") + "-Devices")
    $Group = Get-CreateOrGetAzureADGroup -DisplayName $GroupName -Description "Do not change the name of this group. This group is maintained by a runbook"

    #Allign memberships
    Write-Output "[EarlyProduction]::Alligning members of the group '$($Group.DisplayName)' with the ID of '$($Group.ObjectId)'"
    Set-AllignGroupMemberships -Group $Group -AADObjectIDs $GroupMemberIDs
}

################################
#Running GlobalProduction
################################

for ($i = 0; $i -lt $NumberOfGroupsGlobalProduction; $i++) {
    
    #Define variables
    [array]$GroupMemberIDs = ($GlobalProductionGroupings[$i]).ObjectId
    [string]$GroupName = ($PrefixGroupGlobalProduction + ($i + 1).ToString().PadLeft(4,"0") + "-Devices")
    $Group = Get-CreateOrGetAzureADGroup -DisplayName $GroupName -Description "Do not change the name of this group. This group is maintained by a runbook"

    #Allign memberships
    Write-Output "[GlobalProduction]::Alligning members of the group '$($Group.DisplayName)' with the ID of '$($Group.ObjectId)'"
    Set-AllignGroupMemberships -Group $Group -AADObjectIDs $GroupMemberIDs
}

############### Main - End ###############
#endregion

#Completion
Write-Output ("Script completed in {0}" -f (New-TimeSpan -Start $StartTime -End (Get-Date)).ToString("dd' days 'hh' hours 'mm' minutes 'ss' seconds'"))
