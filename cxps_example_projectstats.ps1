param(
    $projectsFile,
    $cx1url,
    $iamurl,
    $tenant,
    $apikey
)

Import-Module .\CxPowerShift

$projectIDList = (get-content $projectsFile)
$scan_limit = 10
$cx1client = NewCx1Client $cx1url $iamurl $tenant $apikey "" #"http://localhost:8080"
$outputFile = "Cx1 project scans history.csv"
$outputfileExists = $false

$lastProjectScan = @{}

If (Test-Path -Path $outputFile) {
    $outputfileExists = $true
    $existingData = (Import-Csv $outputFile -Delimiter ";")
    
    $lastPID = ""
    $existingData | foreach-object {
        if ( $_.ProjectID -ne $lastPID ) {
            $lastPID = $_.ProjectID
            $lastProjectScan[$lastPID] = $_.ScanID
        }
    }
}

$stages = @( "SourcePulling", "Queued", "ScanStart", "ScanEnd" )

$regex = @{
    SourcePulling = "fetch-sources-.* started"
    Queued = "sast-rm-.* Queued in sast resource manager"
    ScanStart = "sast-worker-.* started"
    ScanEnd = "sast-worker-.* ended"
}

function getTimestamps( $createdAt, $workflow ) {
    $startTime = [datetime]$createdAt
    $zero = New-TimeSpan -Seconds 0

    $scaninfo = [ordered]@{
        ProjectID = ""
        ProjectName = ""
        ScanID = ""
        Status = ""
        Start = $startTime
        SourcePulling = $zero #"fetch-sources-frankfurt started"
        Queued = $zero #"sast-rm-frankfurt Queued in sast resource manager"
        ScanStart = $zero #"sast-worker-frankfurt started"
        ScanEnd = $zero #"sast-worker-frankfurt ended"
        Finish = $zero #"Scan Completed"
    }

    foreach( $log in $workflow ) {
        $log = $log

        foreach( $stage in $stages ) {
            if ( $log.Info -match $regex[$stage] ) {
                $stampTime = [datetime]$log.Timestamp
                $scaninfo[$stage] = $stampTime
                break
            }
            
            $lastStage = $stage
        }        
    }

    return $scaninfo
}

function GetProjectScanHistory( $Cx1ProjectID ) {
    $offset = 0
    $scan_count = [int]($cx1client.GetScans( 1, $Cx1ProjectID ).filteredTotalCount)

    Write-Host "Project $Cx1ProjectID has $scan_count scans total"

    do {
        $scans = $cx1client.GetScans( $scan_limit, $Cx1ProjectID, "", "+created_at", $offset )
    
        foreach( $scan in $scans.scans) {
            if ( $scan.id -eq $lastProjectScan[$Cx1ProjectID] ) {
                Write-Host "Project $Cx1ProjectID scan $($scan.id) already in excel - skipping remaining scans"
                return 
            } else {
                Write-Host "Processing project $Cx1ProjectID scan $($scan.id)"
            }
            $workflow = $cx1client.GetScanWorkflow( $scan.id )
            $stamps = getTimestamps $scan.createdAt $workflow
    
            $stamps.ProjectID = $Cx1ProjectID
            $stamps.ProjectName = $scan.projectName
            $stamps.ScanID = $scan.id
            $stamps.Status = $scan.status
            $stamps.Finish = $scan.updatedAt

            Add-Content -Path $outputFile -Value "$($stamps.ProjectID);$($stamps.ProjectName);$($stamps.ScanID);$($stamps.Status);$($stamps.Start);$($stamps.SourcePulling);$($stamps.Queued);$($stamps.ScanStart);$($stamps.ScanEnd);$($stamps.Finish)"
        }
    
        $offset += $scan_limit
    
    } until ( $offset -gt $scan_count )
}

if ( -Not $outputfileExists ) {
    Add-Content -Path $outputFile -Value "ProjectID;ProjectName;ScanID;Status;Start;Source Pulling;Queued;Scan Start;Scan End;Finish"
}

$projectIDList | foreach-object {
    GetProjectScanHistory $_
}



Remove-Module CxPowerShift