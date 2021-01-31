<#
.SYNOPSIS
  .

.DESCRIPTION
  Will create Windows 10 update update rings CSP profiles 

.NOTES
  Version:        1.0
  Author:         Morten Rønborg (mr@zwable.com)
  Creation Date:  31-01-2021
  Purpose/Change: WuFB Hydration
#>

#Variables
$IntuneClientID = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
$TenantName = "" #change according to tenant e.g. contoso.com

$Win10DeploymentRings = @(

    #Deployment rings for early adopters
    @{ProfileName = "Win10UpdateRing-MEMEarlyAdopters-0001";Description = "Update ring for Early Adpoters";QualityDeferDays = 0;FeatureDeferDays = 0;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMEarlyAdopters-0002";Description = "Update ring for Early Adpoters";QualityDeferDays = 0;FeatureDeferDays = 0;DriversExcluded = $true }

    #Deployment rings for early verification
    @{ProfileName = "Win10UpdateRing-MEMEarlyVerification-0001";Description = "Update ring for Early Verification";QualityDeferDays = 3;FeatureDeferDays = 28;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMEarlyVerification-0002";Description = "Update ring for Early Verification";QualityDeferDays = 3;FeatureDeferDays = 28;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMEarlyVerification-0003";Description = "Update ring for Early Verification";QualityDeferDays = 3;FeatureDeferDays = 28;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMEarlyVerification-0004";Description = "Update ring for Early Verification";QualityDeferDays = 3;FeatureDeferDays = 28;DriversExcluded = $true }

    #Deployment rings for early production
    @{ProfileName = "Win10UpdateRing-MEMEarlyProduction-0001";Description = "Update ring for Early Production";QualityDeferDays = 7;FeatureDeferDays = 56;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMEarlyProduction-0002";Description = "Update ring for Early Production";QualityDeferDays = 7;FeatureDeferDays = 56;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMEarlyProduction-0003";Description = "Update ring for Early Production";QualityDeferDays = 7;FeatureDeferDays = 63;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMEarlyProduction-0004";Description = "Update ring for Early Production";QualityDeferDays = 7;FeatureDeferDays = 63;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMEarlyProduction-0005";Description = "Update ring for Early Production";QualityDeferDays = 8;FeatureDeferDays = 70;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMEarlyProduction-0006";Description = "Update ring for Early Production";QualityDeferDays = 8;FeatureDeferDays = 70;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMEarlyProduction-0007";Description = "Update ring for Early Production";QualityDeferDays = 8;FeatureDeferDays = 77;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMEarlyProduction-0008";Description = "Update ring for Early Production";QualityDeferDays = 8;FeatureDeferDays = 77;DriversExcluded = $true }

    #Deployment rings for early production
    @{ProfileName = "Win10UpdateRing-MEMGlobalProduction-0001";Description = "Update ring for Global Production";QualityDeferDays = 14;FeatureDeferDays = 84;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMGlobalProduction-0002";Description = "Update ring for Global Production";QualityDeferDays = 15;FeatureDeferDays = 91;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMGlobalProduction-0003";Description = "Update ring for Global Production";QualityDeferDays = 16;FeatureDeferDays = 98;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMGlobalProduction-0004";Description = "Update ring for Global Production";QualityDeferDays = 17;FeatureDeferDays = 105;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMGlobalProduction-0005";Description = "Update ring for Global Production";QualityDeferDays = 18;FeatureDeferDays = 112;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMGlobalProduction-0006";Description = "Update ring for Global Production";QualityDeferDays = 19;FeatureDeferDays = 119;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMGlobalProduction-0007";Description = "Update ring for Global Production";QualityDeferDays = 20;FeatureDeferDays = 126;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMGlobalProduction-0008";Description = "Update ring for Global Production";QualityDeferDays = 21;FeatureDeferDays = 133;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMGlobalProduction-0009";Description = "Update ring for Global Production";QualityDeferDays = 22;FeatureDeferDays = 140;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMGlobalProduction-0010";Description = "Update ring for Global Production";QualityDeferDays = 23;FeatureDeferDays = 147;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMGlobalProduction-0011";Description = "Update ring for Global Production";QualityDeferDays = 24;FeatureDeferDays = 154;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMGlobalProduction-0012";Description = "Update ring for Global Production";QualityDeferDays = 25;FeatureDeferDays = 161;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMGlobalProduction-0013";Description = "Update ring for Global Production";QualityDeferDays = 26;FeatureDeferDays = 168;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMGlobalProduction-0014";Description = "Update ring for Global Production";QualityDeferDays = 27;FeatureDeferDays = 175;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMGlobalProduction-0015";Description = "Update ring for Global Production";QualityDeferDays = 28;FeatureDeferDays = 182;DriversExcluded = $true }
    @{ProfileName = "Win10UpdateRing-MEMGlobalProduction-0016";Description = "Update ring for Global Production";QualityDeferDays = 29;FeatureDeferDays = 188;DriversExcluded = $true }
)
Function Initialize-ActiveDirectoryAssemblies
{
    #Get AzureAD module.
    $AzureAdModule = (Get-Module -Name AzureAD -ListAvailable)

    #Get ADAL and ADAL platform assemblies.
    $Adal = Join-Path -Path $AzureAdModule.ModuleBase -ChildPath "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
    $AdalPlatform = Join-Path -Path $AzureAdModule.ModuleBase -ChildPath "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    #Load assemblies.
    [System.Reflection.Assembly]::LoadFrom($Adal) | Out-Null
    [System.Reflection.Assembly]::LoadFrom($AdalPlatform) | Out-Null
}
function Get-GraphAuthToken{

    param(
        [Parameter(Mandatory=$true)] $TenantName,
        [Parameter(Mandatory=$true)] $ClientID
    )

    #Define variables
    $RedirectUri = "urn:ietf:wg:oauth:2.0:oob"
    $ResourceAppIdURI = "https://graph.microsoft.com"
    $Authority = "https://login.microsoftonline.com/$TenantName"

    #Define Auth Context
    $AuthContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $Authority

    #Define Prompt Behaviour
    $PromptBehaviour = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Always

    #Define auth platform parameters
    $AuthParam = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList $PromptBehaviour

    #Try to autheticate
    $AuthenticationTask = $AuthContext.AcquireTokenASync($ResourceAppIdURI, $ClientID,$RedirectUri,$AuthParam)

    #Wait for user input
    $AuthenticationTask.Wait()

    #Get result
    $AuthenticationResult = $AuthenticationTask.Result

    #If the access token is granted.
    If($AuthenticationResult.AccessToken)
    {

        #Create authentication header to return.
        $AuthenticationHeader = @{
            'Content-Type' = 'application/json';
            'Authorization' = "Bearer " + $AuthenticationResult.AccessToken;
            'ExpiresOn' = $AuthenticationResult.ExpiresOn;
        };

        #Return authentication header.
        Return $AuthenticationHeader

    }else {
      
      #Exit
      Write-Host "failed to get auth token"
      break
    }

}
Function New-Win10UpdateRing
{
    Param
    (
        [Parameter(Mandatory=$true)]$AuthToken,
        [Parameter(Mandatory=$true)]$DisplayName,
        [Parameter(Mandatory=$true)]$Description,
        [Parameter(Mandatory=$true)]$DriversExcluded,
        [Parameter(Mandatory=$true)]$QualityDeferDays,
        [Parameter(Mandatory=$true)]$FeatureDeferDays

    )

    #Create reqeust body.
    $Body = @{
        '@odata.type' = '#microsoft.graph.windowsUpdateForBusinessConfiguration';
        'displayName' = $DisplayName;
        'description' = $Description;
        'driversExcluded' = $DriversExcluded;
        'microsoftUpdateServiceAllowed' = $true; 
        'qualityUpdatesDeferralPeriodInDays' =  $QualityDeferDays;
        'featureUpdatesDeferralPeriodInDays' = $FeatureDeferDays;
        'automaticUpdateMode' = '2';
        'businessReadyUpdatesOnly' =  'businessReadyOnly';
        'autoInstallAtMaintenanceTime' = '2';
        'qualityUpdatesPaused' = $false;
        'featureUpdatesPaused' = $false;
        'prereleaseFeatures' = '3';
        'autoRestartNotificationDismissal' = '2';
        'scheduleRestartWarningInHours'= '8';
        'scheduleImminentRestartWarningInMinutes' = '60';
        'userPauseAccess' = '2';
        'userWindowsUpdateScanAccess' = '1';
        'updateNotificationLevel' =  'defaultNotifications';
        'installationSchedule' = @{
            '@odata.type' =  "#microsoft.graph.windowsUpdateActiveHoursInstall";
            'activeHoursStart' =  "08:00:00.0000000";
            'activeHoursEnd' =  "17:00:00.0000000";
        }

    } | ConvertTo-Json

    #Create request headers.
    $Headers = $AuthToken;
    $Headers["content-length"] = $Body.Length
    $Headers["content-type"] = "application/json"

    #Create application in Intune.
    $Reponse = Invoke-RestMethod -Method Post -Headers $Headers -Body $Body -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations" -ContentType "application/json"

    #Return reponse
    Return $Reponse;
}
### start main ###
##################

#Change TLS (needed on some machines)
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

#Import modules
Import-Module AzureADPreview -Scope CurrentUser -AllowClobber -Force

#Inizialize AAD library
Initialize-ActiveDirectoryAssemblies

#Get token for Intune
$IntuneGraphToken  = Get-GraphAuthToken -Tenantname $TenantName -ClientID $IntuneClientID 

#Create Groups
ForEach($Win10DeploymentRing in $Win10DeploymentRings.GetEnumerator()){
    
    #Create the ring
    New-Win10UpdateRing -AuthToken $IntuneGraphToken `
                        -DisplayName $Win10DeploymentRing.ProfileName `
                        -Description $Win10DeploymentRing.Description `
                        -QualityDeferDays $Win10DeploymentRing.QualityDeferDays `
                        -FeatureDeferDays $Win10DeploymentRing.FeatureDeferDays `
                        -DriversExcluded $Win10DeploymentRing.DriversExcluded
}
