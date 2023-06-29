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

$projectIDList = (get-content $projectsFile)
$cx1client = NewCx1Client $cx1url $iamurl $tenant $apikey "" 
$outputFile = "Cx1 project scans history.csv"
$scan_limit = 10

$stages = @( "Queued", "Running", "SourcePulling", "ScanQueued", "ScanStart", "ScanEnd" )

$regex = @{
    SourcePulling = "fetch-sources-.* started"
    Running = "Scan running"
    Queued = "reached, scan queued"
    ScanQueued = "Queued in sast resource manager"
    ScanStart = "sast-worker-.* started"
    ScanEnd = "sast-worker-.* ended"
}


$lastProjectScan = @{}

If (Test-Path -Path $outputFile) {
    $existingData = Import-Csv $outputFile
    
    $lastPID = ""
    $existingData | foreach-object {
        if ( $_.ProjectID -ne $lastPID ) {
            $lastPID = $_.ProjectID
            $lastProjectScan[$lastPID] = $_.ScanID
        }
    }
}

function getScanInfo( $createdAt, $workflow ) {
    $startTime = [datetime]$createdAt
    $zero = New-TimeSpan -Seconds 0

    $scaninfo = [PSCustomObject]@{
        ProjectID = ""
        ProjectName = ""
        ScanID = ""
        Status = ""
        FailReason = ""
        LOC = 0
        FileCount = 0
        Incremental = $false
        Preset = ""
        Start = $startTime
        Queued = $zero #"Max concurent scans reached, scan queued (Position: 40)"
        Running = $zero #"Scan running"
        SourcePulling = $zero #"fetch-sources-frankfurt started"
        ScanQueued = $zero #"sast-rm-frankfurt Queued in sast resource manager"
        ScanStart = $zero #"sast-worker-frankfurt started"
        ScanEnd = $zero #"sast-worker-frankfurt ended"
        Finish = $zero #"Scan Completed"
    }

    foreach( $log in $workflow ) {
        $log = $log

        foreach( $stage in $stages ) {
            if ( $log.Info -match $regex[$stage] ) {
                $stampTime = [datetime]$log.Timestamp
                $scaninfo.$stage = $stampTime
                break
            }
        }        
    }

    return $scaninfo
}
function GetProjectScanHistory( $Cx1ProjectID, $startTime ) {
    $offset = 0
    $scan_count = [int]($cx1client.GetScans( 1, $Cx1ProjectID ).filteredTotalCount)

    Write-Host "Project $Cx1ProjectID has $scan_count scans total"

    do {
        $scans = $cx1client.GetScans( $scan_limit, $Cx1ProjectID, "", "+created_at", $offset )
    
        foreach( $scan in $scans.scans) {
            if ( [datetime]::Parse( $scan.createdAt ) -lt $startTime ) {
                Write-Host "Project $Cx1ProjectID scan $($scan.id) created at $($scan.createdAt) - before cutoff $startTime "
                return
            }
            if ( $scan.id -eq $lastProjectScan[$Cx1ProjectID] ) {
                Write-Host "Project $Cx1ProjectID scan $($scan.id) already in excel - skipping remaining scans"
            } else {
                Write-Host "Processing project $Cx1ProjectID scan $($scan.id)"
            
                $workflow = $cx1client.GetScanWorkflow( $scan.id )
                $scanInfo = getScanInfo $scan.createdAt $workflow

                try {
                    $metadata = $cx1client.GetScanSASTMetadata( $scan.id )
                    $scanInfo.LOC = $metadata.loc
                    $scanInfo.FileCount = $metadata.fileCount
                    $scanInfo.Incremental = $metadata.isIncremental
                    $scanInfo.Preset = $metadata.queryPreset
                } catch {
                    Write-Warning "Failed to get metadata for scan $($scan.id): $_"
                }
                
                if ( $scan.status -eq "Failed" ) {
                    $scanInfo.FailReason = "zeebe" # default fail reason
                    if ( $null -ne $scan.statusDetails ) {
                        foreach ( $reason in $scan.statusDetails ) {
                            if ( $reason.name -eq "sast" ) {
                                if ( $reason.status -eq "failed" ) {
                                    $scanInfo.FailReason = $reason.details
                                }
                            }
                        }
                    }
                }
        
                $scanInfo.ProjectID = $Cx1ProjectID
                $scanInfo.ProjectName = $scan.projectName
                $scanInfo.ScanID = $scan.id
                $scanInfo.Status = $scan.status
                $scanInfo.Finish = $scan.updatedAt

                if (Test-Path -Path $outputFile) {
                    Export-Csv -Path $outputFile -InputObject $scanInfo -NoTypeInformation -Append
                } else {
                    Export-Csv -Path $outputFile -InputObject $scanInfo -NoTypeInformation
                }

                #Add-Content -Path $outputFile -Value "$($stamps.ProjectID);$($stamps.ProjectName);$($stamps.ScanID);$($stamps.Status);$failReason;$($metadata.loc);$($metadata.fileCount);$($metadata.isIncremental);$($metadata.queryPreset);$($stamps.Start);$($stamps.Queued);$($stamps.SourcePulling);$($stamps.ScanQueued);$($stamps.ScanStart);$($stamps.ScanEnd);$($stamps.Finish)"
            }
        }
    
        $offset += $scan_limit
    
    } until ( $offset -gt $scan_count )
}


$projectIDList | foreach-object {
    GetProjectScanHistory $_ $startTime
}

Remove-Module CxPowerShift