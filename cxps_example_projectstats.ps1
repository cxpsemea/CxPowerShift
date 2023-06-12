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

If (Test-Path -Path $outputFile) { Remove-Item -Path $outputFile -Force}



$stages = @( "SourcePulling", "Queued", "ScanStart", "ScanEnd", "Finish" )

$regex = @{
    SourcePulling = "fetch-sources-.* started"
    Queued = "sast-rm-.* Queued in sast resource manager"
    ScanStart = "sast-worker-.* started"
    ScanEnd = "sast-worker-.* ended"
    Finish = "Scan Completed"
}

function getTimestamps( $workflow ) {
    $startTime = [datetime]$workflow[0].Timestamp
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

    $workflow | foreach-object {
        $log = $_

        $stages | foreach-object {
            $stage = $_
            if ( $log.Info -match $regex[$stage] ) {
                $time_offset = ([datetime]$log.Timestamp) - $startTime
                $scaninfo[$stage] = $time_offset
            }
        }        
    }

    return $scaninfo
}

function GetProjectScanHistory( $Cx1ProjectID ) {
    $offset = 0
    $scan_count = $cx1client.GetScans( 1, $Cx1ProjectID ).filteredTotalCount

    Write-Host "Project $Cx1ProjectID has $scan_count scans total"

    do {
        $scans = $cx1client.GetScans( $scan_limit, $Cx1ProjectID, "", "+created_at", $offset )
    
        $scans.scans | foreach-object {
            $workflow = $cx1client.GetScanWorkflow( $_.id )
            $stamps = getTimestamps $workflow
    
            $stamps.ProjectID = $Cx1ProjectID
            $stamps.ProjectName = $_.projectName
            $stamps.ScanID = $_.id
            $stamps.Status = $_.status
            Add-Content -Path $outputFile -Value "$($stamps.ProjectID);$($stamps.ProjectName);$($stamps.ScanID);$($stamps.Status);$($stamps.Start);$($stamps.SourcePulling);$($stamps.Queued);$($stamps.ScanStart);$($stamps.ScanEnd);$($stamps.Finish)"
        }
    
        $offset += $scan_limit
    
    } until ( $offset -gt $scan_count )
}

Add-Content -Path $outputFile -Value "ProjectID;ProjectName;ScanID;Status;Start;Source Pulling;Queued;Scan Start;Scan End;Finish;"

$projectIDList | foreach-object {
    GetProjectScanHistory $_
}



Remove-Module CxPowerShift