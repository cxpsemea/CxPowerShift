param(
    $cx1url,
    $iamurl,
    $tenant,
    $apikey,
    $proxy
)

Import-Module .\CxPowerShift

$cx1client = NewCx1Client $cx1url $iamurl $tenant $apikey $proxy



$inf = $cx1client.ToString()
Write-Host $inf

Write-Host $cx1client.GetApplications(10)
Write-Host $cx1client.GetProjects(10)
Write-Host $cx1client.GetScans(10)



$project = $cx1client.CreateProject( "CxPowerShift" )
Write-Host "Created project $project"


$scanConfig = @(
    @{
        type = "sast"
        value = @{
            incremental = "false"
            presetName = "Checkmarx Default"
        }
    }
) # array of configs


$scan = $cx1client.RunGitScan( $project.id, "https://github.com/michaelkubiaczyk/ssba", "master", $scanConfig )

while ($scan.status -eq "Running" ) {
    Start-Sleep 10
    $scan = $cx1client.GetScan( $scan.id )
    Write-Host " - scan status: $($scan.status)"
}

$cx1client.DeleteScan( $scan.id )
Write-Host "Deleted scan $scan"

$cx1client.DeleteProject( $project.id )
Write-Host "Deleted project $project"

Remove-Module CxPowerShift