param(
    $cx1url,
    $iamurl,
    $tenant,
    $apikey
)

Import-Module .\CxPowerShift

$scan_limit = 10
$cx1client = NewCx1Client $cx1url $iamurl $tenant $apikey "" #"http://localhost:8080"
$cx1client.SetShowErrors($false)

If (-not(Test-Path -Path "out") ) {
    Write-Host "Creating output directory 'out'"
    mkdir out
}



$totalFailedScans = $cx1client.GetScans(0,"","Failed","+created_at",0).filteredTotalCount

$offset = 0
do {
    Write-Host "Getting failed scans $offset - $($offset+$scan_limit) out of $totalFailedScans"
    $scans = $cx1client.GetScans($scan_limit,"","Failed","+created_at",$offset).scans
    
    foreach ( $scan in $scans ) {
        try {
            $workflow = $cx1client.GetScanWorkflow( $scan.id )

            $outputFile = ".\out\$($scan.id)-workflow.csv"
            If (Test-Path -Path $outputFile) {
                Remove-Item -Path $outputFile -Force
            }
            $workflow | Export-Csv -Path $outputFile -NoTypeInformation
            Write-Host "`tCreated $($scan.id)-workflow.csv"
        } catch {
            Write-Warning "Failed to get/store workflow for scan $($scan.id)"
        }

        try {
            $engineLog = $cx1client.GetScanSASTEngineLog( $scan.id )
            $outputFile = ".\out\$($scan.id)-sastlog.txt"
            If (Test-Path -Path $outputFile) {
                Remove-Item -Path $outputFile -Force
            }
            Add-Content -Path $outputfile -Value $engineLog
            Write-Host "`tCreated $($scan.id)-sastlog.txt"
        } catch {
            Write-Warning "Failed to get/store engine logs for scan $($scan.id)"
        }
    }

    $offset += $scan_limit
} until ( $offset -ge $totalFailedScans )



Remove-Module CxPowerShift