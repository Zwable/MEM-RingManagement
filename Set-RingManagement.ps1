<#
.SYNOPSIS

.DESCRIPTION

.NOTES
  Version:        2.0
  Author:         Morten Rønborg (mr@endpointadmin.com)
#>

#Variables
#Early Adopters
[string]$Ring1UserGroupName = "Sec-MEM-EarlyAdopters-Users"  # Supports nested groups (excluding device objects)
[string]$Ring1DeviceGroupName = "Sec-MEM-EarlyAdopters-Devices" # Supports nested groups (excluding user objects)
[string]$PrefixGroupRing1 = "Sec-AutoRunbook-MEMEarlyAdopters-" # Prefix of ring groups
[string]$SuffixGroupRing1 = "-Devices"
[int]$NumberOfGroupsRing1 = 2 # Number of groups in this ring which devices will be spread equally on (this cannot be changed after first run)

#Early verification
[string]$Ring2UserGroupName = "Sec-MEM-EarlyVerification-Users" # Supports nested groups (excluding device objects)
[string]$Ring2DeviceGroupName = "Sec-MEM-EarlyVerification-Devices" # Supports nested groups (excluding user objects)
[string]$PrefixGroupRing2 = "Sec-AutoRunbook-MEMEarlyVerification-"
[string]$SuffixGroupRing2 = "-Devices"
[int]$NumberOfGroupsRing2 = 4 # Number of groups in this ring which devices will be spread equally on (this cannot be changed after first run)

#Early production
[string]$Ring3UserGroupName = "Sec-MEM-EarlyProduction-Users" # Supports nested groups (excluding device objects)
[string]$Ring3DeviceGroupName = "Sec-MEM-EarlyProduction-Devices" # Supports nested groups (excluding user objects)
[string]$PrefixGroupRing3 = "Sec-AutoRunbook-MEMEarlyProduction-"
[string]$SuffixGroupRing3 = "-Devices"
[int]$NumberOfGroupsRing3 = 8 # Number of groups in this ring which devices will be spread equally on (this cannot be changed after first run)

#Global production
[string]$Ring4DeviceGroupName = "Sec-MEM-GlobalProduction-Devices" # Supports nested groups (excluding user objects)
[string]$PrefixGroupRing4 = "Sec-AutoRunbook-MEMGlobalProduction-"
[string]$SuffixGroupRing4 = "-Devices"
[int]$NumberOfGroupsRing4 = 16 # Number of groups in this ring which devices will be spread equally on (this cannot be changed after first run)

#Global excluded devices
[string]$GroupExcludedDevicesName = "Sec-AutoRunbook-MEMDeviceRingsExcluded" # Supports nested groups (excluding user objects)

#Webhook notifictation
$EnableTeamsNotification = $false
$JobName = "Device Ring Management"
$PictureBase64 = "data:image/jpeg;base64,"
$WebHookUrl = ""

#Start
$StartTime = Get-Date

#region begin functions
############### Functions - Start ###############
function Send-Teams {
    param (
        $Title = "Runbook status message",
        $StatusText = "Ring management",
        $JobName = "JobName",
        $JobTitle = "JobTitle",
        $Ring1Text = "N/A",
        $Ring2Text = "N/A",
        $Ring3Text = "N/A",
        $Ring4Text = "N/A",
        $ExcludedText = "N/A",
        $IncludedText = "N/A",
        $URL,
        $Image = "None"
    )

    $body = ConvertTo-Json -Depth 4 @{
        title = $Title
        text = $StatusText
        sections = @(
            @{
                activityTitle =  $JobName
                activitySubtitle = $JobTitle
                activityText = $StatusText
                activityImage = $Image 
                
            },
            @{
                title = 'Details'
                facts = @(
                    @{
                    name = 'Ring 1 :'
                    value = $Ring1Text
                    },
                    @{
                    name = 'Ring 2 :'
                    value = $Ring2Text
                    },
                    @{
                    name = 'Ring 3 :'
                    value = $Ring3Text
                    },
                    @{
                    name = 'Ring 4 :'
                    value = $Ring4Text
                    },
                    @{
                    name = 'Total excluded objects :'
                    value = $ExcludedText
                    },
                    @{
                    name = 'Total included objects:'
                    value = $IncludedText
                    }
                )
            }
        )
        potentialAction = @(@{
            '@context' = 'http://schema.org'
            '@type' = 'ViewAction'
            name = 'Click here to go to the Azure portal'
            target = @("https://portal.azure.com")
        })
    }

    #Invoke rest method
    $Response = Invoke-RestMethod -uri $URL -Method Post -body $body -ContentType 'application/json'
}
function Split-Array {
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
function Get-AzureADGroup {
    param (
        [Parameter(Mandatory=$true)]$AuthHeader,
        [Parameter(Mandatory=$true)]$Search
    )

    #Create request headers.
    $Headers = $AuthHeader
    $Headers["ConsistencyLevel"] = "eventual"
    $Headers["content-type"] = "application/json"

    #Do the call
    $Group = Invoke-RestMethod -Method Get -Headers $Headers -Uri "https://graph.microsoft.com/beta/groups?`$search=$Search" -ContentType "application/json"

    #Return reponse
    return [array]$Group.value
}
function Get-AzureADUserOwnedDevice {
    param (
        [Parameter(Mandatory=$true)]$AuthHeader,
        [Parameter(Mandatory=$true)]$Id
    )

    #Create request headers.
    $Headers = $AuthHeader
    $Headers["content-type"] = "application/json"

    #Do the call
    $Devices = Invoke-RestMethod -Method Get -Headers $Headers -Uri "https://graph.microsoft.com/beta/users/$Id/ownedDevices" -ContentType "application/json"

    #Return reponse
    return [array]$Devices.value
}
function Get-AzureADDevice {
    param (
        [Parameter(Mandatory=$true)]$AuthHeader
    )


    #Create request headers.
    $Headers = $AuthHeader
    $Headers["content-type"] = "application/json"

    #Create application in Intune.
    $Response = Invoke-RestMethod -Method Get -Headers $Headers -Uri "https://graph.microsoft.com/beta/devices?`$filter=startswith(operatingSystem, 'Windows')" -ContentType "application/json"

    #In case the list is longer than 100 items
    while ($Response."@odata.nextLink") {
        
        #Add members and do call
        $Members += $Response.value
        $Response = Invoke-RestMethod -Method Get -Headers $Headers -Uri $Response."@odata.nextLink" -ContentType "application/json"
    }

    #Members
    $Members += $Response.value

    #Return reponse
    return [array]$Members

}
function Add-AzureADGroupMember {
    param (
        [Parameter(Mandatory=$true)]$AuthHeader,
        [Parameter(Mandatory=$true)]$GroupID,
        [Parameter(Mandatory=$false)]$MemberID
    )

    #Create request headers.
    $Headers = $AuthHeader
    $Headers["content-type"] = "application/json"

    #Split into array of 20 (limit by API)
    $MemberGroups = Split-Array -InArray $MemberID -Size 20
    
    #Graph body
    foreach($MemberGroup in $MemberGroups){

        #Define constants
        $Body = @{}
        $Body['members@odata.bind'] = @()

        #Add each ID
        foreach($id in $MemberGroup){
            $Body['members@odata.bind'] += "https://graph.microsoft.com/beta/directoryObjects/$id"
        }

        #Convert body to JSON
        $Json = $Body | ConvertTo-Json

        #Do the call
        $Response = Invoke-RestMethod -Method Patch -Headers $Headers -Body $json -Uri "https://graph.microsoft.com/beta/groups/$GroupID" -ContentType "application/json"
    }
}
function Remove-AzureADGroupMember {
    param (
        [Parameter(Mandatory=$true)]$AuthHeader,
        [Parameter(Mandatory=$true)]$GroupID,
        [Parameter(Mandatory=$true)]$MemberID
    )

    #Create request headers
    $Headers = $AuthHeader
    $Headers["content-type"] = "application/json"

    #Do the call
    $Response = Invoke-RestMethod -Method Delete -Headers $Headers -Uri "https://graph.microsoft.com/beta/groups/$GroupID/members/$MemberID/`$ref" -ContentType "application/json"
}
function Get-AzureADGroupMembers {
    param (
        [Parameter(Mandatory=$true)]$AuthHeader,
        [Parameter(Mandatory=$true)]$GroupID
    )

    #Create request headers.
    $Headers = $AuthHeader
    $Headers["content-type"] = "application/json"
    $Members = @()

    #Do the call
    $Response = Invoke-RestMethod -Method Get -Headers $Headers -Uri "https://graph.microsoft.com/beta/groups/$GroupID/members?`$select=id,displayName,description" -ContentType "application/json"

    #In case the list is longer than 100 items
    while ($Response."@odata.nextLink") {
        
        foreach ($ValueObject in $Response.value) {

            #Add members and do call
            $Obj = [PSCustomObject]@{
                '@odata.type' = $ValueObject."@odata.type"
                id = $ValueObject.Id
                displayName =  $ValueObject.displayName
                groupId =  $GroupID
            }
            $Members += $Obj
        }

        $Response = Invoke-RestMethod -Method Get -Headers $Headers -Uri $Response."@odata.nextLink" -ContentType "application/json"
    }

    #Add members
    foreach ($ValueObject in $Response.value) {

        #Add members and do call
        $Obj = [PSCustomObject]@{
            '@odata.type' = $ValueObject."@odata.type"
            id = $ValueObject.Id
            displayName =  $ValueObject.displayName
            groupId =  $GroupID
        }
        $Members += $Obj
    }

    #Return reponse
    return [array]$Members
}
function Get-AzureADNestedGroupObjects {
    Param
    (
        [Parameter(Mandatory=$true)]$AuthHeader,
        [Parameter(Mandatory=$true)]$GroupObj
    )

    #Get the AD object, and get group membership
    $Members = Get-AzureADGroupMembers -AuthHeader $AuthHeader -GroupID $GroupObj.id

    #Foreach member in the group.
    Foreach($Member in $Members)
    {

        #If the member is a group.
        If($Member."@odata.type" -eq "#microsoft.graph.group")
        {
            #Run the function again against the group
            $Objects += Get-AzureADNestedGroupObjects -AuthHeader $AuthHeader -GroupObj $Member
        }
        Else
        {

            #Add the object to the object array
            If(!($Member.id -in $Objects.id)){

                #Add to the array
                $Objects += @($Member)
            }
        }
    }

    #Return the users (in case object belongs to multiple nested groups, get unique)
    Return ($Objects | Sort-Object -Property id -Unique)
}
function New-AzureADGroup {
    param (
        [Parameter(Mandatory=$true)]$AuthHeader,
        [Parameter(Mandatory=$true)]$DisplayName,
        [Parameter(Mandatory=$true)]$Description

    )
    
    #Graph connection strings.
    $Body = @{
        "displayName" = $DisplayName
        "mailEnabled" = $false
        "mailNickname" = $DisplayName
        "securityEnabled" = $true
        "description" = $Description
    } | ConvertTo-Json

    #Create request headers
    $Headers = $AuthHeader
    $Headers["content-type"] = "application/json"

    #Create group
    $Response = Invoke-RestMethod -Method Post -Headers $Headers -Body $Body -Uri "https://graph.microsoft.com/beta/groups" -ContentType "application/json"

    #Return object
    return $Response
}
function Get-CreateOrGetAzureADGroup {
    param (
        [Parameter(Mandatory=$true)]$AuthHeader,
        [Parameter(Mandatory=$true)]$DisplayName,
        [Parameter(Mandatory=$true)]$Description
    )

    #Get group
    $Group = Get-AzureADGroup -AuthHeader $AuthHeader -Search ("`"description:{0}`" AND `"displayName:{1}`"" -f $Description,$DisplayName)

    #Create if not there
    if([string]::IsNullOrEmpty($Group)){

        #Create the group
        Write-Output ("[Get-CreateOrGetAzureADGroup]::The group '{0}' does not exist. Creating it..." -f $DisplayName)
        $Group = New-AzureADGroup -AuthHeader $AuthHeader -DisplayName $DisplayName -Description $Description
        
        #Add a timeout for  the API to do changes in the Graph database, otherwise adding members will not work in some cases as the
        #group object is still not present in the backend for the add group members function api
        Start-Sleep 30
    }
    
    #Return group
    return $Group
}
function Invoke-RingGroupsMembershipAlligment {
    param (
        $GroupPrefix,
        $GrpoupSuffix,
        $NumberOfGroups,
        $GroupMembers,
        $AuthHeader
    )

    #Write output
    Write-Output "[Invoke-RingGroupsMembershipAlligment]::Starting ring memebership alligment..."

    #Get all members of all ring subgroups
    for ($i = 0; $i -lt $NumberOfGroups; $i++) {

        #Define variables
        [string]$GroupName = ($GroupPrefix + ($i + 1).ToString().PadLeft(4,"0") + $GrpoupSuffix)
        $Group = Get-CreateOrGetAzureADGroup -AuthHeader $AuthHeader -DisplayName $GroupName -Description "Do not change the name or description of this group. This group is maintained by a runbook"
        [array]$AllGroups += $Group

        #Write output
        Write-Output "[Invoke-RingGroupsMembershipAlligment]::Fetching members of the group '$GroupName'"

        #Get all members of the groups
        [array]$CurrentRingMembers += (Get-AzureADGroupMembers -AuthHeader $AuthHeader -GroupID $Group.id)
    }

    #Remove the members that is not supposed to be there
    [array]$MembersToRemove = $CurrentRingMembers | Where-Object{$_.Id -notin $GroupMembers.Id}
    foreach ($Member in $MembersToRemove) {
        
        #Remove member
        Write-Output "[Invoke-RingGroupsMembershipAlligment]::Removing member '$($Member.id)' from the group '$($Member.groupId)'"
        Remove-AzureADGroupMember -AuthHeader $AuthHeader -GroupID $Member.groupId -MemberId $Member.id
        $CurrentRingMembers = $CurrentRingMembers | Where-Object{$_.id -notin $Member.id}
    }

    #Define members to add, how many in each group
    [array]$AllMembersToAdd = $GroupMembers | Where-Object{$_.Id -notin $CurrentRingMembers.Id}
    $MaxGroupMemberships = [Math]::Ceiling(($AllMembersToAdd.Count + $CurrentRingMembers.Count) / $NumberOfGroups)
    $CurrentRingMembersGrouped = $CurrentRingMembers | Group-Object -Property groupId | Sort-Object -Property Count
    
    #Write output
    Write-Output "[Invoke-RingGroupsMembershipAlligment]::Maximum group members in each sub group in this ring '$($MaxGroupMemberships)'"
    Write-Output "[Invoke-RingGroupsMembershipAlligment]::Total group members in this ring '$($CurrentRingMembers.count)'"
    Write-Output "[Invoke-RingGroupsMembershipAlligment]::Total group members to add in this ring '$($AllMembersToAdd.count)'"

    #First go through all empty groups
    foreach ($Group in ($AllGroups | Where-Object {$_.id -notin $CurrentRingMembers.groupId})) {
        
        if($AllMembersToAdd.Count -gt 0){

            #Define variables
            $MembersToAdd = $AllMembersToAdd[0..($MaxGroupMemberships - 1)]

            #Add objects (adding allows to add in bulks 2021-10-13)
            Write-Output "[Invoke-RingGroupsMembershipAlligment]::Adding '$($MembersToAdd.count)' objects to the group '$($Group.displayName)'"
            Add-AzureADGroupMember -AuthHeader $AuthHeader -GroupID $Group.id -MemberId $MembersToAdd.Id

            #Remove from objects to add
            $AllMembersToAdd = $AllMembersToAdd | Where-Object{$_.id -notin $MembersToAdd.id}
        }
    }

    #Go through existing groups
    foreach ($Group in $CurrentRingMembersGrouped) {
        
        if($AllMembersToAdd.Count -gt 0){

            #Define variables
            $NeededMembersInGroup = ($MaxGroupMemberships - $Group.Count)
            $MembersToAdd = $AllMembersToAdd[0..($NeededMembersInGroup - 1)]
            Write-Output "[Invoke-RingGroupsMembershipAlligment]::Adding '$($MembersToAdd.count)' objects to the group '$($Group.Name)'"

            #Add objects (adding allows to add in bulks 2021-10-13)
            Add-AzureADGroupMember -AuthHeader $AuthHeader -GroupID $Group.Name -MemberId $MembersToAdd.Id

            #Remove from objects to add
            $AllMembersToAdd = $AllMembersToAdd | Where-Object{$_.id -notin $MembersToAdd.id}
        }
    }
}
############### Functions - End ###############
#endregion
#region begin main
############### Main - Start ###############
try {

    #Obtain AccessToken for Microsoft Graph via the managed identity
    $ResourceURL = "https://graph.microsoft.com/" 
    $Response = [System.Text.Encoding]::Default.GetString((Invoke-WebRequest -UseBasicParsing -Uri "$($env:IDENTITY_ENDPOINT)?resource=$resourceURL" -Method 'GET' -Headers @{'X-IDENTITY-HEADER' = "$env:IDENTITY_HEADER"; 'Metadata' = 'True'}).RawContentStream.ToArray()) | ConvertFrom-Json 

    #Construct AuthHeader
    $AuthHeader = @{
        'Content-Type' = 'application/json'
        'Authorization' = "Bearer " + $Response.access_token
    }

}
catch {

    #Exit if failed to get access token
    if($EnableTeamsNotification){
        Send-Teams -JobName $JobName -JobTitle "Failed" -StatusText ("Execution failed with: {0}" -f $_) -URL $WebHookUrl -Image $PictureBase64
    }
    Throw $_
}

#Get all current supported PC types
try {
    [array]$AllSupportedWinDevices = Get-AzureADDevice -AuthHeader $AuthHeader
}
catch {

    #Exit if failed to get az devices
    if($EnableTeamsNotification){
        Send-Teams -JobName $JobName -JobTitle "Failed" -StatusText ("Execution failed with: {0}" -f $_) -URL $WebHookUrl -Image $PictureBase64
    }
    Throw $_
}


#Get/Create user groups
$Ring1UserGroup = Get-CreateOrGetAzureADGroup -AuthHeader $AuthHeader -DisplayName $Ring1UserGroupName -Description "Do not change the name or description of this group. This group contains users for Ring 1"
$Ring2UserGroup = Get-CreateOrGetAzureADGroup -AuthHeader $AuthHeader -DisplayName $Ring2UserGroupName -Description "Do not change the name or description of this group. This group contains users for Ring 2"
$Ring3UserGroup = Get-CreateOrGetAzureADGroup -AuthHeader $AuthHeader -DisplayName $Ring3UserGroupName -Description "Do not change the name or description of this group. This group contains users for Ring 3"

#Get/Create device groups
$Ring1DeviceGroup = Get-CreateOrGetAzureADGroup -AuthHeader $AuthHeader -DisplayName $Ring1DeviceGroupName -Description "Do not change the name or description of this group. This group contains devices for Ring 1"
$Ring2DeviceGroup = Get-CreateOrGetAzureADGroup -AuthHeader $AuthHeader -DisplayName $Ring2DeviceGroupName -Description "Do not change the name or description of this group. This group contains devices for Ring 2" 
$Ring3DeviceGroup = Get-CreateOrGetAzureADGroup -AuthHeader $AuthHeader -DisplayName $Ring3DeviceGroupName -Description "Do not change the name or description of this group. This group contains devices for Ring 3"
$Ring4DeviceGroup = Get-CreateOrGetAzureADGroup -AuthHeader $AuthHeader -DisplayName $Ring4DeviceGroupName -Description "Do not change the name or description of this group. This group contains devices for Ring 4"
$GroupExcludedDevices = Get-CreateOrGetAzureADGroup -AuthHeader $AuthHeader -DisplayName $GroupExcludedDevicesName -Description "Do not change the name or description of this group. This group contains devices excluded from the rings. Nested groups are supported. User objects will be ignored."

#Get devices for device groups, we need to exclude these from the global scope as they need to be enforced to each ring later
[array]$Ring1GroupDevices = Get-AzureADNestedGroupObjects -AuthHeader $AuthHeader -GroupObj $Ring1DeviceGroup | Where-Object {$_."@odata.type" -eq "#microsoft.graph.device"}
[array]$Ring2GroupDevices = Get-AzureADNestedGroupObjects -AuthHeader $AuthHeader -GroupObj $Ring2DeviceGroup | Where-Object {$_."@odata.type" -eq "#microsoft.graph.device"}
[array]$Ring3GroupDevices = Get-AzureADNestedGroupObjects -AuthHeader $AuthHeader -GroupObj $Ring3DeviceGroup | Where-Object {$_."@odata.type" -eq "#microsoft.graph.device"}
[array]$Ring4GroupDevices = Get-AzureADNestedGroupObjects -AuthHeader $AuthHeader -GroupObj $Ring4DeviceGroup | Where-Object {$_."@odata.type" -eq "#microsoft.graph.device"}
[array]$AllExcludedDevices = Get-AzureADNestedGroupObjects -AuthHeader $AuthHeader -GroupObj $GroupExcludedDevices | Where-Object {$_."@odata.type" -eq "#microsoft.graph.device"}

#Remove the excluded devices from the allsupported win devcices
[array]$AllSupportedWinDevices = $AllSupportedWinDevices | Where-Object {$_.Id -notin $AllExcludedDevices.Id}

#Define all global group
[array]$GlobalWinDevices = $AllSupportedWinDevices | Where-Object {($_.Id -notin $Ring1GroupDevices.Id) `
                                                    -and ($_.Id -notin $Ring2GroupDevices.Id) `
                                                    -and ($_.Id -notin $Ring3GroupDevices.Id) `
                                                    -and ($_.Id -notin $Ring4GroupDevices.Id)}

################################
#Running define device groupings
################################

#Allign Ring1 groups with users devices (Primary Devices in Intune)
[array]$Ring1UserGroupMembers = Get-AzureADNestedGroupObjects -AuthHeader $AuthHeader -GroupObj $Ring1UserGroup | Where-Object {$_."@odata.type" -eq "#microsoft.graph.user"}
Foreach($User in $Ring1UserGroupMembers){

    #Add all users Primary Devices to an array and ensure they are part of the supported device list
    [array]$Ring1Devices += (Get-AzureADUserOwnedDevice -AuthHeader $AuthHeader  -Id $User.Id | Where-Object {$_.Id -in $GlobalWinDevices.Id}) 
}

#Allign Ring2 groups with users devices (Primary Devices in Intune)
[array]$Ring2UserGroupMembers = Get-AzureADNestedGroupObjects -AuthHeader $AuthHeader -GroupObj $Ring2UserGroup | Where-Object {$_."@odata.type" -eq "#microsoft.graph.user"}
Foreach($User in $Ring2UserGroupMembers){

    #Add all users Primary Devices to an array and ensure they are part of the supported device list (sort out devices from Ring1 as users can be in more groups)
    [array]$Ring2Devices += (Get-AzureADUserOwnedDevice -AuthHeader $AuthHeader  -Id $User.Id | Where-Object {($_.Id -in $GlobalWinDevices.Id) -and ($_.Id -notin $Ring1Devices.Id)})
}

#Allign Ring2 groups with users devices (Primary Devices in Intune)
[array]$Ring3UserGroupMembers = Get-AzureADNestedGroupObjects -AuthHeader $AuthHeader -GroupObj $Ring3UserGroup | Where-Object {$_."@odata.type" -eq "#microsoft.graph.user"}
Foreach($User in $Ring3UserGroupMembers){

    #Add all users Primary Devices to an array and ensure they are part of the supported device list (sort out devices from Ring1 and Ring2 as users can be in more groups)
    [array]$Ring3Devices += (Get-AzureADUserOwnedDevice -AuthHeader $AuthHeader  -Id $User.Id | Where-Object {($_.Id -in $GlobalWinDevices.Id) -and ($_.Id -notin $Ring1Devices.Id) -and ($_.Id -notin $Ring2Devices.Id)})
}

#Remove all the Primary User based devices from the device pool before defining major groups
[array]$AllSupportedWinDevicesNoPrimaryDevices = $GlobalWinDevices | Where-Object{($_.Id -notin $Ring1Devices.Id) -and ($_.Id -notin $Ring2Devices.Id) -and ($_.Id -notin $Ring3Devices.Id)} | Sort-Object -Property Id

#Add the amout of devices to each major ring (use unique as one device can have multiple owners)
[array]$AllRing1Devices = ($Ring1Devices + $Ring1GroupDevices) | Sort-Object -Property Id -Unique
[array]$AllRing2Devices = ($Ring2Devices + $Ring2GroupDevices) | Where-Object {($_.Id -notin $AllRing1Devices.Id)} | Sort-Object -Property Id -Unique
[array]$AllRing3Devices = ($Ring3Devices + $Ring3GroupDevices) | Where-Object {($_.Id -notin $AllRing1Devices.Id) -and ($_.Id -notin $AllRing2Devices.Id)} | Sort-Object -Property Id -Unique
[array]$AllRing4Devices = ($AllSupportedWinDevicesNoPrimaryDevices[0..$AllSupportedWinDevicesNoPrimaryDevices.Count] + $Ring4GroupDevices) | Where-Object {($_.Id -notin $AllRing1Devices.Id) -and ($_.Id -notin $AllRing2Devices.Id) -and ($_.Id -notin $AllRing3Devices.Id)} | Sort-Object -Property Id -Unique

#Write statistics to output
$Ring1Text = "$($AllRing1Devices.Count) ($($Ring1GroupDevices.Count) from $Ring1DeviceGroupName)"
$Ring2Text = "$($AllRing2Devices.Count) ($($Ring2GroupDevices.Count) from $Ring2DeviceGroupName)"
$Ring3Text = "$($AllRing3Devices.Count) ($($Ring3GroupDevices.Count) from $Ring3DeviceGroupName)"
$Ring4Text = "$($AllRing4Devices.Count) ($($Ring4GroupDevices.Count) from $Ring4DeviceGroupName)"
@"
[Rings]::Device statistics:
Ring1: $Ring1Text
Ring2: $Ring2Text
Ring3: $Ring3Text
Ring4: $Ring4Text
Total excluded devices: $($AllExcludedDevices.Count)
Total included devices: $($AllSupportedWinDevices.Count)
"@ | Write-Output

#Invoke alligment
Invoke-RingGroupsMembershipAlligment -GroupPrefix $PrefixGroupRing1 -GrpoupSuffix $SuffixGroupRing1 -NumberOfGroups $NumberOfGroupsRing1 -GroupMembers $AllRing1Devices -AuthHeader $AuthHeader 
Invoke-RingGroupsMembershipAlligment -GroupPrefix $PrefixGroupRing2 -GrpoupSuffix $SuffixGroupRing2 -NumberOfGroups $NumberOfGroupsRing2 -GroupMembers $AllRing2Devices -AuthHeader $AuthHeader 
Invoke-RingGroupsMembershipAlligment -GroupPrefix $PrefixGroupRing3 -GrpoupSuffix $SuffixGroupRing3 -NumberOfGroups $NumberOfGroupsRing3 -GroupMembers $AllRing3Devices -AuthHeader $AuthHeader 
Invoke-RingGroupsMembershipAlligment -GroupPrefix $PrefixGroupRing4 -GrpoupSuffix $SuffixGroupRing4 -NumberOfGroups $NumberOfGroupsRing4 -GroupMembers $AllRing4Devices -AuthHeader $AuthHeader 

#Completion
$CompletionText = ("Script completed in {0}" -f (New-TimeSpan -Start $StartTime -End (Get-Date)).ToString("dd' days 'hh' hours 'mm' minutes 'ss' seconds'"))
Write-Output $CompletionText
if ($EnableTeamsNotification) {
    Send-Teams -JobName $JobName -JobTitle "Completed" -StatusText $CompletionText -Ring1Text $Ring1Text -Ring2Text $Ring2Text -Ring3Text $Ring3Text -Ring4Text $Ring4Text -ExcludedText $($AllExcludedDevices.Count) -IncludedText $($AllSupportedWinDevices.Count) -URL $WebHookUrl -Image $PictureBase64
}
############### Main - End ###############
#endregion