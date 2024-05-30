param(
    [string]$cx1url,
    [string]$iamurl,
    [string]$tenant,
    [string]$apikey,
    [string]$report,
    [string]$projectTagKey = "",
    [string]$projectTagKeyFile = "",
    [string]$projectTagValue = "",
    [string]$projectTagValueFile = "",    
    [string]$scanTagKey = "",
    [string]$scanTagKeyFile = "",
    [string]$scanTagValue = "",
    [string]$scanTagValueFile = "",
    [string]$application = "",
    [string]$applicationFile = "",
    [string]$group = "",
    [string]$groupFile = "",
    [bool]$includeResultHistory = $false,
    [bool]$debug = $false
)

## this example will provide a json-format listing of all findings for all projects matching the specified criteria
## you can apply single-value filters, or pass in a file containing one filter per line
## for example using the parameter $group = "test" would show only the projects that belong to the group "test"
## however you can also use $groupFile = group_list.txt, where group_list.txt contains one group name per line, to filter for projects in any of the listed groups
## all filters (tag value, tag key, application, and group) are AND'ed together, so all filters must match

function GetLastScanWithTags( $cx1client, $projectid, $tagkeys, $tagvalues ) {
    $totalCount = $cx1client.GetScans( 0, $projectid, "Completed" ).filteredTotalCount
    $limit = 10

    for ($offset = 0; $offset -lt $totalCount; $offset += $limit ) {
        $scans = $cx1client.GetScans( $limit, $projectid, "Completed", "+created_at", $offset ).scans
        foreach ( $scan in $scans ) {
            foreach ( $tag in $scan.tags ) {
                foreach ( $prop in $tag.PSObject.Properties ) {
                    if ( $tagkeys.Contains( $prop.Name ) -or $tagvalues.Contains( $prop.Value ) ) {
                        return $scan
                    }
                }
            }
        }
    }

    return $null
}

try {

    Import-Module .\CxPowerShift

    $cx1client = NewCx1Client $cx1url $iamurl $tenant $apikey "" "" ""


    $groupFilter = @()
    $groupIDFilter = @()

    if ( "" -ne $groupFile ) {
        if ( Test-Path $groupFile ) {
            $lines = Get-Content $groupFile
            foreach ( $line in $lines ) {
                if ( -Not $line -eq "" ) {
                    $groupFilter += ($line.replace("`n","").replace("`r",""))
                }
            }
        } else {
            throw "Group file '$groupFile' does not exist"
        }
    } else {
        if ( "" -ne $group ) {
            $groupFilter += $group
        }
    }

    if ( $groupFilter.Length -gt 0 ) {
        foreach ( $group in $groupFilter ) {
            $groupID = $cx1client.GetGroupByName( $group )
            if ( $groupID.Length -gt 0 ) {
                $groupIDFilter += $groupID[0].id
            }
        }
    }

    $applicationFilter = @()
    $applicationIDsFilter = @()

    if ( "" -ne $applicationFile ) {
        if ( Test-Path $applicationFile ) {
            $lines = Get-Content $applicationFile
            foreach ( $line in $lines ) {
                if ( -Not $line -eq "" ) {
                    $applicationFilter += $line
                }
            }
        } else {
            throw "Application file '$applicationFile' does not exist"
        }
    } else {
        if ( "" -ne $application ) {
            $applicationFilter += $application
        }
    }
    if ( $applicationFilter.Length -gt 0 ) {
        foreach ( $application in $applicationFilter ) {
            $app = $cx1client.GetApplicationByName( $application )
            if ( $null -ne $app ) {
                $applicationIDsFilter += $app.id 
            }
        }
    }

    $projectTagValueFilter = @()

    if ( "" -ne $projectTagValueFile ) {
        if ( Test-Path $projectTagValueFile ) {
            $lines = Get-Content $projectTagValueFile
            foreach ( $line in $lines ) {
                if ( -Not $line -eq "" ) {
                    $projectTagValueFilter += $line
                }
            }
        } else {
            throw "Tag Value file '$projectTagValueFile' does not exist"
        }
    } else {
        if ( "" -ne $projectTagValue ) {
            $projectTagValueFilter += $projectTagValue
        }
    }

    $projectTagKeyFilter = @()

    if ( "" -ne $projectTagKeyFile ) {
        if ( Test-Path $projectTagKeyFile ) {
            $lines = Get-Content $projectTagKeyFile
            foreach ( $line in $lines ) {
                if ( -Not $line -eq "" ) {
                    $projectTagKeyFilter += $line
                }
            }
        } else {
            throw "projectTagKey file '$projectTagKeyFile' does not exist"
        }
    } else {
        if ( "" -ne $projectTagKey ) {
            $projectTagKeyFilter += $projectTagKey
        }
    }

    $scanTagValueFilter = @()

    if ( "" -ne $scanTagValueFile ) {
        if ( Test-Path $scanTagValueFile ) {
            $lines = Get-Content $scanTagValueFile
            foreach ( $line in $lines ) {
                if ( -Not $line -eq "" ) {
                    $scanTagValueFilter += $line
                }
            }
        } else {
            throw "Tag Value file '$scanTagValueFile' does not exist"
        }
    } else {
        if ( "" -ne $scanTagValue ) {
            $scanTagValueFilter += $scanTagValue
        }
    }

    $scanTagKeyFilter = @()

    if ( "" -ne $scanTagKeyFile ) {
        if ( Test-Path $scanTagKeyFile ) {
            $lines = Get-Content $scanTagKeyFile
            foreach ( $line in $lines ) {
                if ( -Not $line -eq "" ) {
                    $scanTagKeyFilter += $line
                }
            }
        } else {
            throw "scanTagKey file '$scanTagKeyFile' does not exist"
        }
    } else {
        if ( "" -ne $scanTagKey ) {
            $scanTagKeyFilter += $scanTagKey
        }
    }

    if ( $groupFilter.Length -eq 0 -and $projectTagKeyFilter.Length -eq 0 -and $projectTagValueFilter.Length -eq 0 -and $applicationIDsFilter.Length -eq 0 -and $scanTagKeyFilter.Length -eq 0 -and $scanTagValueFilter.Length -eq 0 ) {
        throw "No filters were defined"
    }
    if ( $debug ) {
        Write-Output "$($groupFilter.Length) group filters"
        Write-Output "$($projectTagKeyFilter.Length) projectTagKey filters"
        Write-Output "$($projectTagValueFilter.Length) projectTagValue filters"
        Write-Output "$($applicationFilter.Length) application filters"
        Write-Output "$($scanTagKeyFilter.Length) scanTagKey filters"
        Write-Output "$($scanTagValueFilter.Length) scanTagValue filters"
    }

    $projects = $cx1client.FindProjects( 0, 0, "", $groupIDFilter, $projectTagKeyFilter, $projectTagValueFilter )
    if ($debug) { Write-Output "Retrieved $($projects.totalCount) total, $($projects.filteredTotalCount) filtered projects" }

    $projectList = @()

    if ( $applicationIDsFilter.Length -eq 0 ) {
        $projectList = $projects.projects
    } else {
        foreach ( $project in $projects.projects ) {
            foreach ( $appId in $project.applicationIds ) {
                if ( $applicationIdsFilter.Contains( $appId ) ) {
                    $projectList += $project
                    break
                }
            }
        }
    }

    Write-Output "There are $($projectList.Length) projects in-scope based on the provided filters, fetching scans"
    
    $scanList = @()
    foreach ( $project in $projectList ) {
        if ($debug) { Write-Output "Fetching scans for project $($project.id) $($project.name)" }

        if ( $scanTagKeyFilter.Length -eq 0 -and $scanTagValueFilter.Length -eq 0 ) {
            $scan = $cx1client.GetScans( 1, $project.id, "Completed" ).scans
            if ($debug) { Write-Output "- project has $($scan.Length) scans" }
            if ( $null -ne $scan -and $scan.Length -gt 0 ) {
                $scanList += $scan[0]
            } else {
                Write-Output "Project $($project.name) [$($project.id)] has no completed scan"
            }
        } else {
            $scan = GetLastScanWithTags $cx1client $project.id $scanTagKeyFilter $scanTagValueFilter
            if ($debug) { Write-Output "- project has $(scan.Length) scans matching scan tag filters" }
            if ( $null -ne $scan ) {
                $scanList += $scan
            } else {
                Write-Output "Project $($project.name) [$($project.id)] has no completed scan matching the provided scan tag filters"
            }
        }
    }

    Write-Output "There are $($scanList.Length) scans in-scope based on the provided filters, fetching results"

    foreach ( $scan in $scanList ) {
        if ($debug) { Write-Output "Fetching results for project $($scan.projectId) $($scan.projectName) scan $($scan.id) from $($scan.createdAt)" }
        $results = $cx1client.GetAllResults( $scan.id )
        if ($debug) { Write-Output "- scan $($scan.id) has $($results.Length) results" }
        foreach ($result in $results) {
            if ( $includeResultHistory) {
                if ($debug) { Write-Output "- fetching status changes/comments" }
                if ($result.type -eq "sast" ) {
                    $preds = $cx1client.GetSASTResultPredicates( $result.similarityId, $scan.projectId )
                    if ( $preds.predicateHistoryPerProject.Length -gt 0 ) {
                        $preds = [array] $preds.predicateHistoryPerProject[0].predicates
                        $result | Add-Member -NotePropertyName predicates -NotePropertyValue $preds
                    }
                } elseif ($result.type -eq "kics" ) {
                    $preds = $cx1client.GetKICSResultPredicates( $result.similarityId, $scan.projectId )
                    if ( $preds.predicateHistoryPerProject.Length -gt 0 ) {
                        $preds = [array] $preds.predicateHistoryPerProject[0].predicates
                        $result | Add-Member -NotePropertyName predicates -NotePropertyValue $preds
                    }
                }
            }
            [string]$queryId = $result.data.queryId
            $result.data.psobject.properties.Remove('queryId')
            $result.data | Add-Member -NotePropertyName queryId -NotePropertyValue $queryId
        }
        $scan | Add-Member -NotePropertyName results -NotePropertyValue $results
    }

    $scanList | ConvertTo-Json -Depth 30 | Out-File $report

} catch {
    Write-Output "Error: $_"
} finally {
    Remove-Module CxPowerShift
}

