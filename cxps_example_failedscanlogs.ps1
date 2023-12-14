param(
    $cx1url,
    $iamurl,
    $tenant,
    $apikey
)

Import-Module .\CxPowerShift

$scan_limit = 10
$cx1client = NewCx1Client $cx1url $iamurl $tenant $apikey "" "" ""#"http://localhost:8080"
$cx1client.SetShowErrors($false)

If (-not(Test-Path -Path "out") ) {
    Write-Host "Creating output directory 'out'"
    mkdir out
}



$totalFailedScans = $cx1client.GetScans(0,"","Failed","+created_at",0).filteredTotalCount

$summary = @()

$offset = 0
do {
    Write-Host "Getting failed scans $offset - $($offset+$scan_limit) out of $totalFailedScans"
    $scans = $cx1client.GetScans($scan_limit,"","Failed","+created_at",$offset).scans
    
    foreach ( $scan in $scans ) {
        $scanSummary = [pscustomobject]@{
            ProjectID = $scan.projectId
            ProjectName = $scan.projectName
            ScanID = $scan.id
            CreatedAt = $scan.createdAt
            FailedAt = $scan.updatedAt
            LastWorkflow = ""
            LastIntegration = ""
            EngineLog = $false
        }

        try {
            $workflow = $cx1client.GetScanWorkflow( $scan.id )

            $outputFile = ".\out\$($scan.id)-workflow.csv"
            If (Test-Path -Path $outputFile) {
                Remove-Item -Path $outputFile -Force
            }
            $workflow | Export-Csv -Path $outputFile -NoTypeInformation

            $count = $workflow.Length - 1
            $show = 3
            if ( $count -lt $show ) { $show = $count }
            for ( $i = $show; $i -ge 0; $i-- ) { 
                $scanSummary.LastWorkflow += "#$($count-$i): $($workflow[$count-$i].Info)"
                if ( $i -gt 0 ) { $scanSummary.LastWorkflow += "`n" }
            }

            Write-Host "`tCreated $($scan.id)-workflow.csv"
        } catch {
            Write-Warning "Failed to get/store workflow for scan $($scan.id)"
        }

        try {
            $integrations = $cx1client.GetScanIntegrationsLog( $scan.id )

            $outputFile = ".\out\$($scan.id)-integrationslog.csv"
            If (Test-Path -Path $outputFile) {
                Remove-Item -Path $outputFile -Force
            }
            $integrations | Export-Csv -Path $outputFile -NoTypeInformation

            $count = $integrations.Length - 1
            $show = 3
            if ( $count -lt $show ) { $show = $count }
            for ( $i = $show; $i -ge 0; $i-- ) { 
                $scanSummary.LastIntegration += "#$($count-$i): $($integrations[$count-$i].Info)"
                if ( $i -gt 0 ) { $scanSummary.LastIntegration += "`n" }
            }

            Write-Host "`tCreated $($scan.id)-integrationslog.csv"
        } catch {
            Write-Warning "Failed to get/store integration log for scan $($scan.id)"
        }

        try {
            $engineLog = $cx1client.GetScanSASTEngineLog( $scan.id )
            $outputFile = ".\out\$($scan.id)-sastlog.txt"
            If (Test-Path -Path $outputFile) {
                Remove-Item -Path $outputFile -Force
            }
            Add-Content -Path $outputfile -Value $engineLog
            Write-Host "`tCreated $($scan.id)-sastlog.txt"

            $scanSummary.EngineLog = $true
        } catch {
            Write-Warning "Failed to get/store engine logs for scan $($scan.id)"
        }

        $summary += $scanSummary
    }


    $offset += $scan_limit
} until ( $offset -ge $totalFailedScans )

$summary | export-csv "Cx1 failed scans summary.csv" -NoTypeInformation

Remove-Module CxPowerShift