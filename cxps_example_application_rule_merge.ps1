param(
    $cx1url,
    $iamurl,
    $tenant,
    $apikey,
    $proxy,
    [bool]$merge
)

Import-Module .\CxPowerShift



try {
    $cx1client = NewCx1Client $cx1url $iamurl $tenant $apikey "" "" $proxy


    Write-Output ($cx1client.ToString())

    $appCount = $cx1client.GetApplications().totalCount
    $apps = $cx1client.GetApplications( $appCount ).applications
    foreach ( $app in $apps ) {
        $status = "OK"
        $count = 0
        $combined = ""
        foreach ( $rule in $app.rules ) {
            if ( $rule.type -eq "project.name.in" ) {
                $count += 1
                if ( $combined -eq "" ) {
                    $combined = $rule.value
                } else {
                    $combined = "$combined;$($rule.value)"
                }
            }
        }

        if ( $count -gt 1 ) {
            $status = "BAD - $count project.name.in rules"
            $appDetails = $cx1client.GetApplicationByID( $app.id )
            #Write-Output $appDetails
            #Write-Output "`n  will become`n"
            $rules = @()
            $count = 0
            foreach ( $rule in $appDetails.rules ) {
                if ( $rule.type -eq "project.name.in" ) {
                    if ( $count -eq 0 ) {
                        $rule.value = $combined
                        $rules += $rule
                    }
                    $count += 1
                } else {
                    $rules += $rule
                }
            }
            $appDetails.rules = $rules
            #Write-Output $appDetails
            
            if ( $merge ) {
                $cx1client.UpdateApplication( $appDetails )
            }

        }
        Write-Output "App $($app.name) - $status"

        
    }
} catch {
    Write-Output "Exception: $_"
} finally {
    Remove-Module CxPowerShift
}
