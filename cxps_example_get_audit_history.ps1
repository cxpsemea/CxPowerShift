param(
    $cx1url,
    $iamurl,
    $tenant,
    $apikey
)

Import-Module .\CxPowerShift

$cx1client = NewCx1Client $cx1url $iamurl $tenant $apikey "" "" ""

$audit = $cx1client.GetAudit($true)
$json = ConvertTo-Json -InputObject $audit -Depth 10
$json | Out-File audit.json

Remove-Module CxPowerShift
