param(
    $cx1url,
    $iamurl,
    $tenant,
    $clientid,
    $clientsecret
)

Import-Module .\CxPowerShift

$cx1client = NewCx1Client $cx1url $iamurl $tenant $null $clientid $clientsecret ""

$clients = $cx1client.GetClients()

foreach ( $client in $clients ) {
    if ( -Not $null -eq $client.attributes.notificationEmail -and  -Not $client.attributes.notificationEmail.Contains( "[" )) {
        Write-Host "$($client.clientId) has old-format notification emails set to: $($client.attributes.notificationEmail)"
        Write-Host "`tUpdating this to: `"[`\`"$($client.attributes.notificationEmail)`\`"]`""
        $client.attributes.notificationEmail = "[`"$($client.attributes.notificationEmail)`"]"
        $cx1client.UpdateClient( $client )
    }

}

Remove-Module CxPowerShift
