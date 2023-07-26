param(
    $projectsFile,
    $cx1url,
    $iamurl,
    $tenant,
    $apikey, 
    $since = ""
)

Import-Module .\CxPowerShift

if ( $since -ne "" ) {
    $startTime = [datetime]::Parse( $since )
} else {
    $startTime = [datetime]::Parse( "2020-01-01 00:00:00")
}
Write-Host "Filtering for scans since $startTime"

$cx1client = NewCx1Client $cx1url $iamurl $tenant $apikey "" 
$outputFile = "Cx1 project scans history.csv"
$scan_limit = 10

if ( $projectsFile -ne "" ) {
    Write-Host "Loading list of project IDs from $projectsFile"
    $projectIDList = (get-content $projectsFile)
} else {
    Write-Host "No project list provided, will get history of all projects"
    $cx1client = NewCx1Client $cx1url $iamurl $tenant $apikey "" 
    $projectCount = $cx1client.GetProjects(0).totalCount
    $projects = $cx1client.GetProjects($projectCount).projects

    $projectIDList = @()
    foreach ( $proj in $projects ) {
        $projectIDList += $proj.id
    }

    Write-Host $projectIDList

    Write-Host "There are $($projectIDList.Length) projects"
}

$lastProjectScan = @{}

If (Test-Path -Path $outputFile) {
    $existingData = Import-Csv $outputFile

    foreach ( $entry in $existingData ) {
        $projectId = $entry.ProjectID
        $scanId = $entry.ScanID
        $startTime = $entry.Start

        if ( (-Not $lastProjectScan.ContainsKey( $projectId )) -or ( $lastProjectScan[$projectId].startTime -lt $startTime )) {
            $lastProjectScan[$projectId] = @{
                scanId = $scanId
                startTime = $startTime
            }
        }
    }
}

function GetProjectScanHistory( $Cx1ProjectID, $startTime ) {
    $offset = 0
    $scan_count = [int]($cx1client.GetScans( 1, $Cx1ProjectID ).filteredTotalCount)

    Write-Host "Project $Cx1ProjectID has $scan_count scans total"

    do {
        $scans = $cx1client.GetScans( $scan_limit, $Cx1ProjectID, "", "+created_at", $offset )
    
        foreach( $scan in $scans.scans) {
            if ( $scan.createdAt -is [string] ) {
                $scan.createdAt = [datetime]::Parse($scan.createdAt)
            }
            $scan.createdAt = $scan.createdAt.ToLocalTime()                    
            
            if ( $scan.createdAt -lt $startTime ) {
                Write-Host "Project $Cx1ProjectID scan $($scan.id) created at $([datetime]::Parse( $scan.createdAt )) - before cutoff $startTime "
                return
            }

            if ( $scan.id -eq $lastScanID ) {
                Write-Host "    Project for $Cx1ProjectID scan $($scan.id) already in excel - skipping remaining scans"
                return
            } else {
                Write-Host "Processing project $Cx1ProjectID scan $($scan.id)"
                $scanInfo = $cx1client.GetScanInfo( $scan )                

                if (Test-Path -Path $outputFile) {
                    Export-Csv -Path $outputFile -InputObject $scanInfo -NoTypeInformation -Append
                } else {
                    Export-Csv -Path $outputFile -InputObject $scanInfo -NoTypeInformation
                }
            }
        }
    
        $offset += $scan_limit
    
    } until ( $offset -gt $scan_count )
}


$projectIDList | foreach-object {
    GetProjectScanHistory $_ $startTime
}

Remove-Module CxPowerShift