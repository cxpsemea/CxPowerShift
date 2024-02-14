param(
    $cx1url,
    $iamurl,
    $tenant,
    $apikey
)

Import-Module .\CxPowerShift

$cx1client = NewCx1Client $cx1url $iamurl $tenant $apikey "" "" ""
Write-Host ($cx1client.ToString())

$queries = $cx1client.GetQueries()
$mappings = $cx1client.GetQueryMappings().mappings

$MappedQueries = @{}
foreach ( $map in $mappings ) {
    $MappedQueries[$map.astID] = $map.sastID
}

$comparison = @()
$ProductQueries = @{}
$CorpQueries = @{}

foreach ( $query in $queries ) {
    if ( $query.level -eq "Cx" ) {
        if ( $ProductQueries.ContainsKey( $query.Id ) ) {
            Write-Output "Duplicate Cx-level Query ID: $($query.Id) ->`n$($query)"
            Write-Output "Previously entered query: $($ProductQueries[$query.Id])"
        } else {
            $ProductQueries.Add( $query.Id, $query )
        }
    } elseif ( $query.level -eq "Corp" ) {
        $CorpQueries.Add( $query.Id, $query )
    }
}

Write-Output "There are $($ProductQueries.count) product-default queries and $($CorpQueries.count) tenant-level queries"

$cx1client.SetShowErrors($false)
foreach ( $queryID in $CorpQueries.Keys ) {
    $query = $CorpQueries[$queryID]

    #Write-Output "Query: $($query.path)"
    $corp_query = $cx1client.GetQuery( "Corp", $query.path )

    if ( $ProductQueries.ContainsKey( $queryID ) ) {
        $path = $query.path
        if ( $ProductQueries[$queryID].path -ne $path ) {
            $path = $ProductQueries[$queryID].path
        }
        try {
            $product_query = $cx1client.GetQuery( "Cx", $query.path )
            $product_query | Add-Member -Name "Query Status" -Type NoteProperty -Value "Product Default"
        } catch {
            if ( $MappedQueries.ContainsKey( $queryID ) ) {
                $product_query = [pscustomobject]@{ 
                    Severity = -1
                    'Query Status' = "Deprecated Query"
                }
            } else {
                #Write-Output "Failed to get $($query.path) on Cx-level"
                $product_query = [pscustomobject]@{ 
                    Severity = -1
                    'Query Status' = "Unknown"
                }
            }
        }
    } else {
        #Write-Output "Query $($query.path) is not product default?"
        $product_query = [pscustomobject]@{ 
            Severity = -1
            'Query Status' = "New Custom Query"
        }
    }

    $comparison += [pscustomobject]@{
        'Query Status' = $product_query.'Query Status'
        QueryID = $queryID
        Language = $query.lang
        Group = $query.group
        Query = $query.name
        'Default Severity' = SeverityToString  $product_query.Severity 
        'Custom Severity' = SeverityToString  $corp_query.Severity 
        'Custom Code' = $corp_query.Source
        'Customized Date' = $corp_query.Modified
    }


    <# If you wanted to delete the query: $cx1client.DeleteQuery( "Corp", $query.path ) #>
}


$comparison | Sort-Object -Property Language,Group,Query | Format-Table 'Query Status', QueryID, Language, Group, Query, 'Default Severity', 'Custom Severity', 'Custom Code', 'Customized Date'

Remove-Module CxPowerShift
