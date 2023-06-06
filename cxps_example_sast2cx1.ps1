param(
    $xmlreport,
    $Cx1ScanID,
    $cx1url,
    $iamurl,
    $tenant,
    $apikey
)

Import-Module .\CxPowerShift


$matchNodeCountDeviation = 1
$Cx1ProjectID = ""


function CompareNodes( $Cx1, $SAST ) {
    if ( $Cx1.line -eq $SAST.Line -and `
         $Cx1.name -imatch $SAST.Name -and `
         $Cx1.column -eq $SAST.Column -and `
         $Cx1.fileName -imatch $SAST.FileName ) {
        return $true
    }
    return $false
}

function UpdateCx1Finding( $Cx1, $SAST ) {
    $severity = $SAST.Severity.ToUpper()
    if ( $severity -eq "INFORMATION" ) {
        $severity = "INFO"
    }
    $state = "TO_VERIFY"
    switch ($SAST.State) {
        1 { $state = "NOT_EXPLOITABLE" }
        2 { $state = "CONFIRMED"}
        3 { $state = "URGENT"}
        4 { $state  = "PROPOSED_NOT_EXPLOITABLE" }
    }

    if ( -Not( $severity -imatch $Cx1.severity ) -or -Not( $state -imatch $Cx1.state ) ) {
        Write-Host " - Updating cx1 finding: $($SAST.Language) - $($SAST.Group) - $($SAST.Name) [$($Cx1.similarityId)] in project $Cx1ProjectID"
        $cx1client.AddResultPredicate( $Cx1.similarityId, $Cx1ProjectID, $severity, $state, $SAST.Comment )
        #Write-Host "`tSeverity: $severity"
        #Write-Host "`tState:    $state"
        #Write-Host "`tComment:  $($SAST.Comment)"
        #Write-Host ""
    } else {
        Write-Host " - Cx1 finding already matches SAST: $($SAST.Language) - $($SAST.Group) - $($SAST.Name) [$($Cx1.similarityId)] in project $Cx1ProjectID"
        #Write-Host "`tSeverity: $severity"
        #Write-Host "`tState:    $state"
        #Write-Host ""
    }
}


function FindMatch( $Cx1Finding, $SASTFindings ) {
    #Write-Host "Checking Cx1 finding: $($Cx1Finding.data.languageName) - $($Cx1Finding.data.group) - $($Cx1Finding.data.queryName) [$($Cx1Finding.similarityId)]"

    for ( $i = 0; $i -lt $SASTFindings.length; $i++ ) {
        #Write-Host " - $i"
        $sf = $SASTFindings[$i]
        if ( $sf.Match -eq $false -and
             $sf.Name -imatch $Cx1Finding.data.queryName -and  `
             $sf.Group -imatch $Cx1Finding.group -and `
             $sf.Language -imatch $Cx1Finding.languageName ) {
            #Write-Host " - Finding type match: $($sf.Language) - $($sf.Group) - $($sf.Name)"
            #Write-Host " - SAST finding has $($sf.Nodes.length) nodes vs $($Cx1Finding.data.nodes.length) in Cx1"
            $nodeDiff = $sf.Nodes.length - $Cx1Finding.data.nodes.length
            if ( $nodeDiff -gt -1*$matchNodeCountDeviation -and $nodeDiff -lt $matchNodeCountDeviation ) { # +/- 1 difference
                if ( (CompareNodes $Cx1Finding.data.nodes[0] $sf.Nodes[0]) -and `
                     (CompareNodes $Cx1Finding.data.nodes[ $Cx1Finding.data.nodes.length - 1 ] $sf.Nodes[ $sf.Nodes.length - 1 ]) ) {
                    #Write-Host " - First and last nodes match"
                    $sf.Match = $true
                    UpdateCx1Finding $Cx1Finding $sf
                    return $true
                }
            }
        }
    }

    return $false
}




$findings = @()

$report = [xml]( Get-Content $xmlreport )

$report.CxXMLResults.Query | foreach-object {
    $query = $_

    $_.Result | foreach-object {
        $result = $_

        $finding = @{
            QueryID = $query.id
            Name = $query.name
            Group = $query.group
            Language = $query.language

            Comment = $result.Remark
            State = $result.State
            Severity = $result.Severity

            Match = $false
        }
        $_.Path | foreach-object {
            [array]$nodes = @()
            
            $_.PathNode | foreach-object {
                $nodes += @{
                    FileName = "/" + $_.FileName
                    Line = $_.Line
                    Column = $_.Column
                    Name = $_.Name
                }
            }

            $finding.Nodes = $nodes
            $finding.SimilarityID = $_.SimilarityId
            $finding.PathID = $_.PathId

            $findings += $finding
        }
    }
}

Write-Host "There were $($findings.length) findings parsed from the report"

$cx1client = NewCx1Client $cx1url $iamurl $tenant $apikey $proxy

$scan = $cx1client.GetScan( $Cx1ScanID )
$Cx1ProjectID = $scan.metadata.project.id

$resultCount = $cx1client.GetResults( $Cx1ScanID, 1 ).totalCount
$results = $cx1client.GetResults( $Cx1ScanID, $resultCount ).results

Write-Host "There are $($results.length) findings in Cx1`n"


Write-Host "Comparing results:"
$matchCount = 0

$results | foreach-object {
    if ( FindMatch $_ $findings ) {
        $matchCount ++
    } else {
        Write-Host "New: Cx1 finding $($Cx1Finding.data.languageName) - $($Cx1Finding.data.group) - $($Cx1Finding.data.queryName) [$($Cx1Finding.similarityId)]"
    }
}

Write-Host ""

if ( $matchCount -eq $findings.length ) {
    Write-Host "All findings from $xmlreport were synchronized to Cx1 scan $Cx1ScanID"
} else {
    Write-Host "The following findings in $xmlreport were not found in Cx1 scan $Cx1ScanID"
    $findings | foreach-object {
        if ( -not $_.Match ) {
            Write-Host " - PathID $($_.PathID): $($_.Language) - $($_.Group) - $($_.Name) [$($_.SimilarityID)]"
        }
    }

}

Remove-Module CxPowerShift