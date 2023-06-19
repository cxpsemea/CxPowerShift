param(
    $cx1url,
    $iamurl,
    $tenant,
    $apikey
)

Import-Module .\CxPowerShift

$cx1client = NewCx1Client $cx1url $iamurl $tenant $apikey ""


Write-Host ($cx1client.ToString())

$scan_limit = 20
$scans = $cx1client.GetScans(0,"","Queued","+created_at",0).filteredTotalCount
$offset = 0

do {
  $scans = $cx1client.GetScans($scan_limit,"","Queued","+created_at",$offset).scans
  foreach ( $scan in $scans ) {
    try {
      $cx1client.CancelScan($scan.id)
    } catch {
      Write-Warning "Failed to cancel $($scan.id)"
    }
  }

  $offset += $scan_limit
} until ( $offset -ge $totalFailedScans )


Remove-Module CxPowerShift
