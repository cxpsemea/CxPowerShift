param(
    $cx1url,
    $iamurl,
    $tenant,
    $apikey
)

Import-Module .\CxPowerShift

$cx1client = NewCx1Client $cx1url $iamurl $tenant $apikey "" "" ""


Write-Host ($cx1client.ToString())

$scan_limit = 20
$totalQueuedScans = $cx1client.GetScans(0,"","Queued","+created_at",0).filteredTotalCount
Write-Host "There are $totalQueuedScans scans Queued"

$count = 0

do {
  $scans = $cx1client.GetScans($scan_limit,"","Queued","+created_at",0).scans
  
  foreach ( $scan in $scans ) {
    Write-Host "Canceling scan $($scan.id)"
    try {
      $cx1client.CancelScan($scan.id)
    } catch {
      Write-Host "Failed to cancel scan $($scan.id)"
    }
  }

  $count += $scans.Length
} until ( $count -ge $totalQueuedScans )


Remove-Module CxPowerShift
