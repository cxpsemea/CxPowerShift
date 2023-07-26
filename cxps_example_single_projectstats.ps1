param(
    $projectID,
    $lastScanID,
    $cx1url,
    $iamurl,
    $tenant,
    $apikey, 
    $since = "",
    $mutex = $null
)

# This script is intended to be called by the threaded_projectstats script but can be used on its own also.

Import-Module .\CxPowerShift

if ( $since -ne "" ) {
    $startTime = [datetime]::Parse( $since )
} else {
    $startTime = [datetime]::Parse( "2020-01-01 00:00:00")
}
#Write-Host "Filtering for scans since $startTime"

$cx1client = NewCx1Client $cx1url $iamurl $tenant $apikey "" 
$outputFile = "Cx1 project scans history.csv"
$scan_limit = 10


function GetProjectScanHistory( $Cx1ProjectID, $startTime ) {
    $offset = 0
    $scan_count = [int]($cx1client.GetScans( 1, $Cx1ProjectID ).filteredTotalCount)

    Write-Host "  Project $Cx1ProjectID has $scan_count scans total"

    do {
        $scans = $cx1client.GetScans( $scan_limit, $Cx1ProjectID, "", "+created_at", $offset )
        Write-Host "    Progress for $($Cx1ProjectID): $($offset+1) / $scan_count - $($scans.scans[0].createdAt)"
        foreach( $scan in $scans.scans) {
            if ( $scan.createdAt -is [string] ) {
                $scan.createdAt = [datetime]::Parse($scan.createdAt)
            }
            $scan.createdAt = $scan.createdAt.ToLocalTime()                    
            
            if ( $scan.createdAt -lt $startTime ) {
                #Write-Host "Project $Cx1ProjectID scan $($scan.id) created at $([datetime]::Parse( $scan.createdAt )) - before cutoff $startTime "
                return
            }

            if ( $scan.id -eq $lastScanID ) {
                Write-Host "    Project for $Cx1ProjectID scan $($scan.id) already in excel - skipping remaining scans"
                return
            } else {
                #Write-Host "Processing project $Cx1ProjectID scan $($scan.id)"
                $scanInfo = $cx1client.GetScanInfo( $scan )

                if ( $null -ne $mutex ) {
                    $mutex.WaitOne()
                }
                if (Test-Path -Path $outputFile) {
                    Export-Csv -Path $outputFile -InputObject $scanInfo -NoTypeInformation -Append
                } else {
                    Export-Csv -Path $outputFile -InputObject $scanInfo -NoTypeInformation
                }
                
                if ( $null -ne $mutex ) {
                    $mutex.ReleaseMutex()
                }
            }
        }
    
        $offset += $scan_limit
    
    } until ( $offset -ge $scan_count )
}


GetProjectScanHistory $projectID $startTime


Remove-Module CxPowerShift