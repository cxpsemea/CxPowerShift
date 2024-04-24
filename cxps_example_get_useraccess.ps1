param(
    $cx1url,
    $iamurl,
    $tenant,
    $apikey, 
    $userEmail,
    $appName,
	$projName
)

Import-Module .\CxPowerShift

try {
    $cx1client = NewCx1Client $cx1url $iamurl $tenant $apikey "" "" ""# "http://localhost:8080" 
} catch {
    Write-Output "Error creating cx1 client: $_"s
    return
}

if ( $userEmail -ne "" ) {
    $users = $cx1client.GetUserByEmail($userEmail)
    if ( $users.Length -eq 0 ) {
        Write-Output "No users found matching email $userEmail"
        return
    } else {
        $targetUser = $users[0]
        Write-Output "User ID for user with email $userEmail is: $($targetUser.id)"
    } 
} else {
    Write-Output "Error: must provide userEmail parameters"
    return
}


$permissions = $cx1client.GetUserPermissions($targetUser.id)

Write-Output "`n=================================`n"
if ($permissions.length -gt 0) {
	Write-Output "User has the following permissions assigned directly:"
	foreach ( $perm in $permissions| Sort-Object -Property "name" ) {
		Write-Output "`t- $($perm.name) ($($perm.id))"
	}
} else {
	Write-Output "User has no direct permissions granted"
}

$groups = $cx1client.GetUserInheritedGroups( $targetUser.id )
Write-Output "`n=================================`n"

if ($groups.length -gt 0) {
	Write-Output "User belongs to the following groups (directly or inherited):"
	foreach ( $group in $groups | Sort-Object -Property "name" ) {
		$group_roles = $cx1client.GetGroupRoles($group.id)
		if ($group_roles.length -gt 0) {
			Write-Output "`t- $($group.name) ($($group.id)) with roles:"
			foreach ( $role in $group_roles | Sort-Object -Property "name" ) {
				Write-Output "`t`t- $($role.name) ($($role.id))"
				if ( -Not($cx1client.ArrayContainsRole( $permissions, $role )) ) {
					$permissions += $role
				}
			}
		} else {
			Write-Output "`t- $($group.name) ($($group.id)) with no roles"
		}
	}
} else {
	Write-Output "User does not belong to any groups"
}
Write-Output "`n=================================`n"

Write-Output "Final set of permissions held by user $($targetUser.username):`n"
$ifingroup = $false
foreach ( $perm in $permissions | Sort-Object -Property "name" ) {
    Write-Output "`t- $($perm.name) ($($perm.id))"
    if ( $perm.name -match "-if-in-group" ) {
        $ifingroup = $true
    }
}

# Get In-Scope projects
if ( $projName -eq "" ) {
    $projectCount = $cx1client.GetProjects(0).totalCount
    $projects = $cx1client.GetProjects($projectCount).projects
} else {
    $projectCount = $cx1client.GetProjects(0, 0, $projName).totalCount
    $projects = $cx1client.GetProjects($projectCount, 0, $projName).projects
}

Write-Output "There are $($projects.length) projects in scope"

# Get In-Scope applications
if ( $appName -ne "" ) {
    $applicationCount = $cx1client.GetApplications(0,0,$appName).totalCount
    $applications = $cx1client.GetApplications($applicationCount,0,$appName).applications
} elseif ( $projName -ne "" ) {
    $appIds = @()
    foreach ( $proj in $projects ) {
        $proj = $cx1client.GetProjectByID($proj.id)
        foreach ($appId in $proj.applicationIds) {
            if ( -Not $appIds.Contains($appId) ) {
                $appIds += $appId
            }
        }
    }
    $applications = @()
    foreach ( $appId in $appIds ) {
        $app = $cx1client.GetApplicationByID($appId)
        $applications += $app
    }
} else { 
    $applicationCount = $cx1client.GetApplications(0).totalCount
    $applications = $cx1client.GetApplications($applicationCount).applications
}

Write-Output "There are $($applications.length) applications in scope"

if ( $ifingroup ) {
    Write-Output "`n=================================`n"
	Write-Output "User has access to the following projects due to *-if-in-group permissions:"

	
    foreach ( $project in $projects ) {
        foreach ( $user_group in $groups ) {
            if ( $project.groups.Contains( $user_group.id ) ) {
                Write-Output "`t- $($project.name) ($($project.id)) - granted through group $($user_group.name) ($($user_group.id)"
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
    Write-Output "`n=================================`n"
    Write-Output "New access management is enabled, checking for assigned access permissions.`n"
    try {
        
        $cx1client.SetShowErrors($false)
        $assignments = $cx1client.GetResourcesAccessibleToEntity( $targetUser.id )
        $cx1client.SetShowErrors($true)
        
        if ($assignments.Length -gt 0 ) {
            Write-Output "The following access assignments exist for this user:"
            foreach ($assignment in $assignments) {
                $roles = "no specific roles"
                if ($assignment.roles.length -gt 0) {
                    $roles = "roles: $(Join-String $assignment.roles)"
                }
                Write-Output "`t$($assignment.type) ID $($assignment.id) with $roles"
            }
        } else {
            Write-Output "No access assignments exist for this user"
        }

    } catch {
        Write-Output "Error getting from /api/access-management/resources-for"
    }

    Write-Output "Iterating over all objects. This may take a while.`n"
    
    Write-Output "Tenant-level assignment for user $($targetUser.username):"
    try {
        $cx1client.SetShowErrors($false)
        $access = $cx1client.GetResourceEntityAssignment( $cx1client.TenantID, $targetUser.id )            
        $cx1client.SetShowErrors($true)
        $roles = @()
        if ( $access.entityRoles.length -gt 0 ) {
            foreach ( $role in $access.entityRoles ) {
                $temp_roles = @()
                $roleObj = $cx1client.GetRoleByName($role.Name)
                $temp_roles += $roleObj
                if ( $roleObj.composite ) {
                    $temp_roles += $cx1client.GetDecomposedRoles($roleObj.id)
                }
                $roles = $cx1client.MergeRoleArrays( $roles, $temp_roles )
            }
        } else {
            Write-Output "`t- generic (no role) access assignment to tenant for user"
        } 
    } catch {
        #Write-Output " - none"
    }
    foreach ( $group in $groups ) {
        try {
            $cx1client.SetShowErrors($false)
            $access = $cx1client.GetResourceEntityAssignment( $cx1client.TenantID, $group.id )            
            $cx1client.SetShowErrors($true)
            if ( $access.entityRoles.length -gt 0 ) {
                foreach ( $role in $access.entityRoles ) {
                    #Write-Output "`t- $role (assignment through group $($group.name) ($($group.id)))"
                    $temp_roles = @()
                    $roleObj = $cx1client.GetRoleByName($role.Name)
                    $temp_roles += $roleObj
                    if ( $roleObj.composite ) {
                        $temp_roles += $cx1client.GetDecomposedRoles($roleObj.id)
                    }
                    $roles = $cx1client.MergeRoleArrays( $roles, $temp_roles )
                }
            } else {
                Write-Output "`t- generic (no role) access assignment to tenant through group $($group.name) ($($group.id)))"
            } 
        } catch {
            #Write-Output " - none"
        }
    }
    if ( $roles.Length -gt 0 ) {
        Write-Output "`tSpecific tenant permissions:"
        foreach ( $role in $roles | Sort-Object -Property "name" ) {
            Write-Output "`t`t- $($role.name) ($($role.id))"   
        }
    } else {
        Write-Output " - none"
    }

    Write-Output "`nApplication-level assignments for user $($targetUser.username):"

    $checkedApps = 0
    foreach( $app in $applications ) {
        $roles = @()
        $checkedApps += 1
        if ( $checkedApps % 10 -eq 0 ) {
            Write-Output " - $checkedApps / $applicationCount apps"
        }
        try {
            $cx1client.SetShowErrors($false)
            $access = $cx1client.GetResourceEntityAssignment( $app.id, $targetUser.id )
            $cx1client.SetShowErrors($true)
            if ( $access.entityRoles.length -gt 0 ) {
                foreach ( $role in $access.entityRoles ) {
                    #Write-Output "`t`t- $role (direct user assignment)"
                    $temp_roles = @()
                    $roleObj = $cx1client.GetRoleByName($role.Name)
                    $temp_roles += $roleObj
                    if ( $roleObj.composite ) {
                        $temp_roles += $cx1client.GetDecomposedRoles($roleObj.id)
                    }
                    $roles = $cx1client.MergeRoleArrays( $roles, $temp_roles )
                }
            } else {
                Write-Output "`t- generic (no role) access assignment to $($app.name) ($($app.id)) for user"
            }                
        } catch {
            #Write-Output " - none"
        }
        foreach ( $group in $groups ) {
            try {
                $cx1client.SetShowErrors($false)
                $access = $cx1client.GetResourceEntityAssignment( $app.id, $group.id )  
                $cx1client.SetShowErrors($true) 
                if ( $access.entityRoles.length -gt 0 ) {
                    foreach ( $role in $access.entityRoles ) {
                        #Write-Output "`t- $role (assignment through group $($group.name) ($($group.id)))"
                        $temp_roles = @()
                        $roleObj = $cx1client.GetRoleByName($role.Name)
                        $temp_roles += $roleObj
                        if ( $roleObj.composite ) {
                            $temp_roles += $cx1client.GetDecomposedRoles($roleObj.id)
                        }
                        $roles = $cx1client.MergeRoleArrays( $roles, $temp_roles )
                    }
                } else {
                    Write-Output "`t- generic (no role) access assignment to $($app.name) ($($app.id)) through group $($group.name) ($($group.id)))"
                }  
            } catch {
                #Write-Output " - none"
            }
        }
        if ( $roles.Length -gt 0 ) {
            Write-Output "`tSpecific application $($app.name) ($($app.id)) permissions:"
            foreach ( $role in $roles | Sort-Object -Property "name" ) {
                Write-Output "`t`t- $($role.name) ($($role.id))"   
            }
        } else {
            Write-Output "`tNo specific application-level permissions."
        }
    }

    Write-Output "`nProject-level assignments for user $($targetUser.username):"
    $checkedProjects = 0
    foreach( $proj in $projects ) {
        $roles = @()
        $checkedProjects += 1
        if ( $checkedProjects % 10 -eq 0 ) {
            Write-Output " - $checkedProjects / $projectCount projects"
        }
        try {
            $cx1client.SetShowErrors($false)
            $access = $cx1client.GetResourceEntityAssignment( $proj.id, $targetUser.id )
            $cx1client.SetShowErrors($true)
            if ( $access.entityRoles.length -gt 0 ) {
                foreach ( $role in $access.entityRoles ) {
                    #Write-Output "`t`t- $role (direct user assignment)"
                    $temp_roles = @()
                    $roleObj = $cx1client.GetRoleByName($role.Name)
                    $temp_roles += $roleObj
                    if ( $roleObj.composite ) {
                        $temp_roles += $cx1client.GetDecomposedRoles($roleObj.id)
                    }
                    $roles = $cx1client.MergeRoleArrays( $roles, $temp_roles )
                }
            } else {
                Write-Output "`t- generic (no role) access assignment to $($proj.name) ($($proj.id)) for user"
            }  
        } catch {
            #Write-Output " - none"
        }
        foreach ( $group in $groups ) {
            try {
                $cx1client.SetShowErrors($false)
                $access = $cx1client.GetResourceEntityAssignment( $proj.id, $group.id )  
                $cx1client.SetShowErrors($true) 
                if ( $access.entityRoles.length -gt 0 ) {                    
                    foreach ( $role in $access.entityRoles ) {
                        #Write-Output "`t- $role (assignment through group $($group.name) ($($group.id)))"
                        $temp_roles = @()
                        $roleObj = $cx1client.GetRoleByName($role.Name)
                        $temp_roles += $roleObj
                        if ( $roleObj.composite ) {
                            $temp_roles += $cx1client.GetDecomposedRoles($roleObj.id)
                        }
                        $roles = $cx1client.MergeRoleArrays( $roles, $temp_roles )
                    }
                } else {
                    Write-Output "`t- generic (no role) access assignment to $($proj.name) ($($proj.id)) through group $($group.name) ($($group.id)))"
                } 
            } catch {
                #Write-Output " - none"
            }
        }

        
        if ( $roles.Length -gt 0 ) {
            Write-Output "`tSpecific project $($proj.name) ($($proj.id)) permissions:"
            foreach ( $role in $roles | Sort-Object -Property "name" ) {
                Write-Output "`t`t- $($role.name) ($($role.id))"   
            }
        } else {
            Write-Output "`tNo specific project-level permissions."
        }
    }
    Write-Output "`n=================================`n"
} else {
    Write-Output "`n=================================`n"
    Write-Output "User has the above regular (not if-in-group) permissions on the following projects:"
    foreach ( $proj in $projects ) {
        Write-Output "`t- $($proj.name) ($($proj.id))"
    }
}


Remove-Module CxPowerShift
