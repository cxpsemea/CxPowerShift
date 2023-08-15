param(
    $cx1url,
    $iamurl,
    $tenant,
    $apikey, 
    $userEmail,
    $userID
)

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
    foreach ( $role in $group_roles | Sort-Object -Property "name" ) {
        Write-Host "`t`t- $($role.name) ($($role.id))"
        if ( -Not($cx1client.ArrayContainsRole( $permissions, $role )) ) {
            $permissions += $role
        }
    }
}
Write-Host "`n=================================`n"
Write-Host "Final set of permissions held by user $($targetUser.username):`n"
$ifingroup = $false
foreach ( $perm in $permissions | Sort-Object -Property "name" ) {
    Write-Host "`t- $($perm.name) ($($perm.id))"
    if ( $perm.name -match "-if-in-group" ) {
        $ifingroup = $true
    }
}


if ( $ifingroup ) {
    Write-Host "`n=================================`n"
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


$flags = $cx1client.GetFlags()

$newIAM = $false
foreach ( $flag in $flags ) {
    if ( $flag.name -eq "ACCESS_MANAGEMENT_ENABLED" ) {
        $newIAM = $flag.status
    }
}

if ( $newIAM ) {
    Write-Host "`n=================================`n"
    Write-Host "New access management is enabled, checking for assigned access permissions.`n"
    try {
        
        $cx1client.SetShowErrors($false)
        $assignments = $cx1client.GetResourcesAccessibleToEntity( $targetUser.id )
        $cx1client.SetShowErrors($true)
        Write-Host "The following access assignments exist for this user: $assignments"
    } catch {
        Write-Host "Error getting from /api/access-management/resources-for - iterating over all objects. This may take a while.`n"
        
        Write-Host "Tenant-level assignment for user $($targetUser.username):"
        try {
            $cx1client.SetShowErrors($false)
            $access = $cx1client.GetResourceEntityAssignment( $cx1client.TenantID, $targetUser.id )            
            $cx1client.SetShowErrors($true)
            $roles = @()
            foreach ( $role in $access.entityRoles ) {
                $temp_roles = @()
                $roleObj = $cx1client.GetRoleByName($role)
                $temp_roles += $roleObj
                if ( $roleObj.composite ) {
                    $temp_roles += $cx1client.GetDecomposedRoles($roleObj.id)
                }
                $roles = $cx1client.MergeRoleArrays( $roles, $temp_roles )
            }
        } catch {
            #Write-Host " - none"
        }
        foreach ( $group in $groups ) {
            try {
                $cx1client.SetShowErrors($false)
                $access = $cx1client.GetResourceEntityAssignment( $cx1client.TenantID, $group.id )            
                $cx1client.SetShowErrors($true)
                foreach ( $role in $access.entityRoles ) {
                    #Write-Host "`t- $role (assignment through group $($group.name) ($($group.id)))"
                    $temp_roles = @()
                    $roleObj = $cx1client.GetRoleByName($role)
                    $temp_roles += $roleObj
                    if ( $roleObj.composite ) {
                        $temp_roles += $cx1client.GetDecomposedRoles($roleObj.id)
                    }
                    $roles = $cx1client.MergeRoleArrays( $roles, $temp_roles )
                }
            } catch {
                #Write-Host " - none"
            }
        }
        if ( $roles.Length -gt 0 ) {
            foreach ( $role in $roles | Sort-Object -Property "name" ) {
                Write-Host "`t- $($role.name) ($($role.id))"   
            }
        } else {
            Write-Host " - none"
        }

        Write-Host "`nApplication-level assignments for user $($targetUser.username):"
        $applicationCount = $cx1client.GetApplications(0).totalCount
        $applications = $cx1client.GetApplications($applicationCount).applications
        $checkedApps = 0
        foreach( $app in $applications ) {
            $roles = @()
            $checkedApps += 1
            if ( $checkedApps % 10 -eq 0 ) {
                Write-Host " - $checkedApps / $applicationCount apps"
            }
            try {
                $cx1client.SetShowErrors($false)
                $access = $cx1client.GetResourceEntityAssignment( $app.id, $targetUser.id )
                $cx1client.SetShowErrors($true)
                foreach ( $role in $access.entityRoles ) {
                    #Write-Host "`t`t- $role (direct user assignment)"
                    $temp_roles = @()
                    $roleObj = $cx1client.GetRoleByName($role)
                    $temp_roles += $roleObj
                    if ( $roleObj.composite ) {
                        $temp_roles += $cx1client.GetDecomposedRoles($roleObj.id)
                    }
                    $roles = $cx1client.MergeRoleArrays( $roles, $temp_roles )
                }
            } catch {
                #Write-Host " - none"
            }
            foreach ( $group in $groups ) {
                try {
                    $cx1client.SetShowErrors($false)
                    $access = $cx1client.GetResourceEntityAssignment( $app.id, $group.id )  
                    $cx1client.SetShowErrors($true) 
                    foreach ( $role in $access.entityRoles ) {
                        #Write-Host "`t- $role (assignment through group $($group.name) ($($group.id)))"
                        $temp_roles = @()
                        $roleObj = $cx1client.GetRoleByName($role)
                        $temp_roles += $roleObj
                        if ( $roleObj.composite ) {
                            $temp_roles += $cx1client.GetDecomposedRoles($roleObj.id)
                        }
                        $roles = $cx1client.MergeRoleArrays( $roles, $temp_roles )
                    }
                } catch {
                    #Write-Host " - none"
                }
            }
            if ( $roles.Length -gt 0 ) {
                Write-Host "`t- $($app.name) ($($app.id)):"
                foreach ( $role in $roles | Sort-Object -Property "name" ) {
                    Write-Host "`t`t- $($role.name) ($($role.id))"   
                }
            }
        }

        Write-Host "`nProject-level assignments for user $($targetUser.username):"
        $projectCount = $cx1client.GetProjects(0).totalCount
        $projects = $cx1client.GetProjects($projectCount).projects
        $checkedProjects = 0
        foreach( $proj in $projects ) {
            $roles = @()
            $checkedProjects += 1
            if ( $checkedProjects % 10 -eq 0 ) {
                Write-Host " - $checkedProjects / $projectCount projects"
            }
            try {
                $cx1client.SetShowErrors($false)
                $access = $cx1client.GetResourceEntityAssignment( $proj.id, $targetUser.id )
                $cx1client.SetShowErrors($true)
                foreach ( $role in $access.entityRoles ) {
                    #Write-Host "`t`t- $role (direct user assignment)"
                    $temp_roles = @()
                    $roleObj = $cx1client.GetRoleByName($role)
                    $temp_roles += $roleObj
                    if ( $roleObj.composite ) {
                        $temp_roles += $cx1client.GetDecomposedRoles($roleObj.id)
                    }
                    $roles = $cx1client.MergeRoleArrays( $roles, $temp_roles )
                }
            } catch {
                #Write-Host " - none"
            }
            foreach ( $group in $groups ) {
                try {
                    $cx1client.SetShowErrors($false)
                    $access = $cx1client.GetResourceEntityAssignment( $proj.id, $group.id )  
                    $cx1client.SetShowErrors($true) 
                    foreach ( $role in $access.entityRoles ) {
                        #Write-Host "`t- $role (assignment through group $($group.name) ($($group.id)))"
                        $temp_roles = @()
                        $roleObj = $cx1client.GetRoleByName($role)
                        $temp_roles += $roleObj
                        if ( $roleObj.composite ) {
                            $temp_roles += $cx1client.GetDecomposedRoles($roleObj.id)
                        }
                        $roles = $cx1client.MergeRoleArrays( $roles, $temp_roles )
                    }
                } catch {
                    #Write-Host " - none"
                }
            }

            
            if ( $roles.Length -gt 0 ) {
                Write-Host "`t- $($proj.name) ($($proj.id)):"
                foreach ( $role in $roles | Sort-Object -Property "name" ) {
                    Write-Host "`t`t- $($role.name) ($($role.id))"   
                }
            }
        }
    }
    Write-Host "`n=================================`n"
}


Remove-Module CxPowerShift