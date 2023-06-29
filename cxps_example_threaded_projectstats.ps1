param(
    $projectsFile,
    $cx1url,
    $iamurl,
    $tenant,
    $apikey, 
    $since = ""
)

$projectIDList = (get-content $projectsFile)
$outputFile = "Cx1 project scans history.csv"


$lastProjectScan = @{}

If (Test-Path -Path $outputFile) {
    $existingData = Import-Csv $outputFile

    $existingData | foreach-object {
        $projectId = $_.ProjectID
        $scanId = $_.ScanID

        if ($lastProjectScan.ContainsKey( $projectId )) {
            break
        } else {
            $lastProjectScan[$projectId] = $scanId
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

    