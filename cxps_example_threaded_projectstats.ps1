param(
    $projectsFile,
    $cx1url,
    $iamurl,
    $tenant,
    $apikey, 
    $since = ""
)

if ( $projectsFile -ne "" ) {
    Write-Host "Loading list of project IDs from $projectsFile"
    $projectIDList = (get-content $projectsFile)
} else {
    Write-Host "No project list provided, will get history of all projects"
    Import-Module .\CxPowerShift
    $cx1client = NewCx1Client $cx1url $iamurl $tenant $apikey "" 
    $projectCount = $cx1client.GetProjects(0).totalCount
    $projects = $cx1client.GetProjects($projectCount).projects

    $projectIDList = @()
    foreach ( $proj in $projects ) {
        $projectIDList += $proj.id
    }

    Write-Host $projectIDList

    Remove-Module CxPowerShift
}
$outputFile = "Cx1 project scans history.csv"


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
$mutex = New-Object System.Threading.Mutex($false, "projectstats")

Write-Host "Creating jobs" 
$jobs = $projectIDList | foreach-object {
    $projectId = $_
    $lastScanId = $lastProjectScan[$projectId]
    Start-ThreadJob -ScriptBlock {
        .\cxps_example_single_projectstats.ps1 $using:projectId $using:lastScanId $using:cx1url $using:iamurl $using:tenant $using:apikey $using:since $using:mutex
    } -ThrottleLimit 5 -Name "Project $projectId" -StreamingHost $Host
}

Write-Host "Waiting for jobs to finish"

do {
    $jobs = Get-Job
    Write-Host "There are $($jobs.Length) jobs left"
    Receive-Job -Job $jobs
    Start-Sleep 5
    Remove-Job -State Completed
    Remove-Job -State Failed
} until ((Get-Job).Length -eq 0)

Write-Host "Jobs Done"

    