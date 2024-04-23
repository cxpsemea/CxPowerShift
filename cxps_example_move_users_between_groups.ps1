param(
    $cx1url,
    $iamurl,
    $tenant,
    $apikey,
    $proxy,
    $sourceGroupName,
    $destGroupName
)

Import-Module .\CxPowerShift

function ChangeAccessAssignment() {
    param (
        [Parameter(Mandatory=$true)][string]$sourceGroupID,
        [Parameter(Mandatory=$true)][string]$destGroupID
    )

    $flags = $cx1client.GetFlags()
    $newIAM = $false
    foreach ( $flag in $flags ) {
        if ( $flag.name -eq "ACCESS_MANAGEMENT_ENABLED" ) {
            $newIAM = $flag.status
        }
    }

    if ( $newIAM ) {
        Write-Output "`n=================================`n"
        Write-Output "New access management is enabled, checking for assigned access permissions.`n"
        $assignments = $cx1client.GetResourcesAccessibleToEntity( $sourceGroupID )
        Write-Output "The following access assignments exist for this user: $assignments"
        Write-Output "`n=================================`n"
    } else {
        Write-Output "hmm..."
    }
}


try {
    $cx1client = NewCx1Client $cx1url $iamurl $tenant $apikey "" "" $proxy
    Write-Output ($cx1client.ToString())

    $sourceGroup = $cx1client.GetGroupByName( $sourceGroupName )
    if ( $null -eq $sourceGroup ) {
        throw "Source group $sourceGroupName not found"
    }
    Write-Output "Source group: $($sourceGroup.name) [$($sourceGroup.id)]"
    $destGroup = $cx1client.GetGroupByName( $destGroupName )
    if ( $null -eq $destGroup ) {
        throw "Source group $destGroupName not found"
    }
    Write-Output "Destination group: $($destGroup.name) [$($destGroup.id)]"

    $sourceUsers = $cx1client.GetGroupMembers( $sourceGroup.id )
    foreach ( $user in $sourceUsers ) {
        Write-Output "Adding user $($user.email) [$($user.id)] to destination group $destGroupName"
        #$ret = $cx1client.AddUserToGroup( $user.id, $destGroup.id )
        Write-Output "Removing user $($user.email) [$($user.id)] from source group $sourceGroupName"
        #$ret = $cx1client.RemoveUserFromGroup( $user.id, $sourceGroup.id )
    }

    ChangeAccessAssignment $sourceGroup.id $destGroup.id
} catch {
    Write-Output "Exception: $_"
} finally {
    Remove-Module CxPowerShift
}


