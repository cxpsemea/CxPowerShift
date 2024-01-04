param(
    $cx1url,
    $iamurl,
    $tenant,
    $clientid,
    $clientsecret,
    $targetClientId,
    $expiryExtension
)

Import-Module .\CxPowerShift

$cx1client = NewCx1Client $cx1url $iamurl $tenant $null $clientid $clientsecret ""

$clients = $cx1client.GetClients()

foreach ( $client in $clients ) {
    #Write-Host "Client $($client.clientId) has expiry $($client.attributes."client.secret.expiration.time")"
    if ( $client.clientId -eq $targetClientId ) {
        Write-Host "$($client.clientId) has expiry time before cutoff: $($client.attributes."client.secret.expiration.time")"
        $expiry = [int]$client.attributes."client.secret.expiration.time" + $expiryExtension
        Write-Host "`tUpdating this to: $expiry"
        $client.attributes."client.secret.expiration.time" = $expiry
        $cx1client.UpdateClient( $client )
    }
}

Remove-Module CxPowerShift
