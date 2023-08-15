param(
    $cx1url,
    $iamurl,
    $tenant,
    $apikey, 
    $userEmail,
    $userID
)

# This script is intended to be called by the threaded_projectstats script but can be used on its own also.

Import-Module .\CxPowerShift

try {
    $cx1client = NewCx1Client $cx1url $iamurl $tenant $apikey "" # "http://localhost:8080" 
} catch {
    Write-Host "Error creating cx1 client: $_"s
    return
}

if ( $userEmail -ne "" ) {
    $users = $cx1client.GetUserByEmail($userEmail)
    if ( $users.Length -eq 0 ) {
        Write-Host "No users found matching email $userEmail"
        return
    } else {
        $targetUser = $users[0]
        Write-Host "User ID for user with email $userEmail is: $($targetUser.id)"
    } 
} elseif ( $userID -ne "" ) {
    $targetUser = $cx1client.GetUserByID( $userID )
} else {
    Write-Host "Error: must provide userID or userEmail parameters"
    return
}


$permissions = $cx1client.GetUserPermissions($targetUser.id)

Write-Host "`n=================================`nUser has the following permissions assigned directly:"
foreach ( $perm in $permissions| Sort-Object -Property "name" ) {
    Write-Host "`t- $($perm.name) ($($perm.id))"
}

$groups = $cx1client.GetUserInheritedGroups( $targetUser.id )
Write-Host "`n=================================`nUser has the following permissions inherited from groups:"

foreach ( $group in $groups | Sort-Object -Property "name" ) {
    Write-Host "`t- $($group.name) ($($group.id))"
    $group_roles = $cx1client.GetGroupRoles($group.id)
    foreach ( $role in $group_roles | Sort-Object ) {
        Write-Host "`t`t- $($role.name) ($($role.id))"
        if ( -Not($cx1client.ArrayContainsRole( $permissions, $role )) ) {
            $permissions += $role
        }
    }
}
Write-Host "`n=================================`n"
Write-Host "Final set of permissions held by user $($userEmail):`n"
$ifingroup = $false
foreach ( $perm in $permissions | Sort-Object -Property "name" ) {
    Write-Host "`t- $($perm.name) ($($perm.id))"
    if ( $perm.name -match "-if-in-group" ) {
        $ifingroup = $true
    }
}
Write-Host "`n=================================`n"


if ( $ifingroup ) {
    Write-Host "User has access to the following projects due to *-if-in-group permissions:"
    $projectCount = $cx1client.GetProjects(0).totalCount
    $projects = $cx1client.GetProjects($projectCount).projects
    foreach ( $project in $projects ) {
        foreach ( $user_group in $groups ) {
            if ( $project.groups.Contains( $user_group.id ) ) {
                Write-Host "`t- $($project.name) ($($project.id)) - granted through group $($user_group.name) ($($user_group.id)"
            }
        }
    }
}


Write-Host "`n=================================`n"
$flags = $cx1client.GetFlags()

$newIAM = $false
foreach ( $flag in $flags ) {
    if ( $flag.name -eq "ACCESS_MANAGEMENT_ENABLED" ) {
        $newIAM = $flag.status
    }
}

if ( $newIAM ) {
    try {
        $assignments = $cx1client.GetResourcesAccessibleToEntity( $targetUser.id )
        Write-Host "The following access assignments exist for this user: $assignments"
    } catch {
        Write-Host "Error getting from /api/access-management/resources-for - iterating over all objects. This may take a while."

    }
    Write-Host "`n=================================`n"
}


Remove-Module CxPowerShift