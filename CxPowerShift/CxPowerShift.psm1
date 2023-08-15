<#
 .Synopsis
  CheckmarxOne REST API client in Powershell

 .Description
  A client that can be used to connect to and manipulate a CheckmarxOne environment via REST API

 .Example
   # Connect to a specific Cx1 instance using an API key
   $cx1Client = NewCx1Client -cx1url https://ast.checkmarx.net -iamurl https://iam.checkmarx.net -tenant my_tenant -apikey secret_key
   # Use the client to do things
   $projects = $cx1Client.Get-Projects
#>

# Get timestamp for Logs
function getTime() {
    return "[{0:MM/dd/yyyy} {0:HH:mm:ss.fff K}]" -f (Get-Date)
}

#log message to Console
function log($message, $warning = $false) {
    $formattedMessage = "$(getTime) ${message}"
    if(!$warning){
        Write-Host $formattedMessage
    } else{
        Write-Warning $formattedMessage
    }
}

function GetToken() {
    $uri = "$($this.IAMUrl)/auth/realms/$($this.Tenant)/protocol/openid-connect/token"
    $body = @{
        client_id = "ast-app"
        refresh_token = (Plaintext($this.APIKey))
        grant_type = "refresh_token"
    } 
    try  {
        $resp = $null
        if ( $this.Proxy -eq "" ) {
            $resp = Invoke-RestMethod -uri $uri -method "POST" -body $body 
        } else {
            $resp = Invoke-RestMethod -uri $uri -method "POST" -body $body -Proxy $this.Proxy
        }

        $this.Token = ConvertTo-SecureString $resp.access_token -AsPlainText -Force
        $this.Expiry = (Get-Date).AddSeconds( $resp.expires_in - 60 ) # let's refresh the token a minute early
    } catch {
        log $_ $true
        $value = $_.Exception.Response.StatusCode.value__
        $description = $_.Exception.Response.StatusDescription
        log "StatusCode: ${value}" 
        log "StatusDescription: ${description}" 
        throw $errorMessage
    }
}

function req($uri, $method, $client, $errorMessage, $body, $proxy){

    if ( $client.Expiry -lt (Get-Date) ) {
        $client.GetToken() # hopefully auto-refresh?
    }
    $token = (Plaintext($client.Token))

    $headers = @{
        Authorization = "Bearer $token"
        "Content-Type" = "application/json;v=1.0"
        "Accept" = "application/json; version=1.0"
    }
    try {
        if($method -eq "POST" -or $method -eq "PUT" -or $method -eq "PATCH" ){
            $body = ConvertTo-Json -InputObject $body -Depth 5
            if ( $proxy -eq "" ) {
                $resp = Invoke-RestMethod -uri $uri -method $method -headers $headers -body $body
            } else {
                $resp = Invoke-RestMethod -uri $uri -method $method -headers $headers -body $body -Proxy $proxy
            }
        } else {
            if ( $proxy -eq "" ) {
                $resp = Invoke-RestMethod -uri $uri -method $method -headers $headers
            } else {
                $resp = Invoke-RestMethod -uri $uri -method $method -headers $headers -Proxy $proxy
            }
        }
        return $resp
    } catch {
        if ( $client.ShowErrors ) {
            log -message $_  -warning $true
            $value = $_.Exception.Response.StatusCode.value__
            $description = $_.Exception.Response.StatusDescription
            log "HTTP ${value} - $uri - StatusDescription: ${description}" $true
            log "Request body was: $($body | ConvertTo-Json)"
        }
        throw $errorMessage
    }
}

function makeURI( $base, [hashtable]$params ) {
    $q = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
    
    foreach ($key in $params.Keys)
    {
        $q.Add($key, $params.$key)
    }
    
    # Build the uri
    $uri = [System.UriBuilder]$base
    $uri.Query = $q.ToString()
    
    return $uri.Uri.OriginalString
}

function Cx1Get {
    param(
        [Parameter(Mandatory=$true)][string]$api,
        [Parameter(Mandatory=$false)]$query,
        [Parameter(Mandatory=$false)][string]$errorMessage = "error getting $uri"
    )
    $uri = makeURI "$($this.Cx1URL)/api/$api" $query
    return req $uri "GET" $this $errorMessage "" $this.Proxy
}
function Cx1Delete {
    param(
        [Parameter(Mandatory=$true)][string]$api,
        [Parameter(Mandatory=$false)][string]$errorMessage = "error deleting $uri"
    )
    $uri = "$($this.Cx1URL)/api/$api"
    return req $uri "DELETE" $this $errorMessage "" $this.Proxy
}
function Cx1Post {
    param(
        [Parameter(Mandatory=$true)][string]$api,
        [Parameter(Mandatory=$false)]$body,
        [Parameter(Mandatory=$false)][string]$errorMessage = "error posting $uri"
    )
    $uri = "$($this.Cx1URL)/api/$api"
    return req $uri "POST" $this $errorMessage $body $this.Proxy
}

function Cx1Patch {
    param(
        [Parameter(Mandatory=$true)][string]$api,
        [Parameter(Mandatory=$false)]$body,
        [Parameter(Mandatory=$false)][string]$errorMessage = "error posting $uri"
    )
    $uri = "$($this.Cx1URL)/api/$api"
    return req $uri "PATCH" $this $errorMessage $body $this.Proxy
}

function IAMGet {
    param(
        [Parameter(Mandatory=$true)][string]$base,
        [Parameter(Mandatory=$true)][string]$api,
        [Parameter(Mandatory=$false)]$query,
        [Parameter(Mandatory=$false)][string]$errorMessage = "error getting $uri"
    )
    $uri = makeURI "$($this.IAMURL)/$base/realms/$($this.Tenant)/$api" $query
    return req $uri "GET" $this $errorMessage "" $this.Proxy
} 

function shorten($str) {
    return $str.Substring(0,4) +".."+ $str.Substring($str.length - 4)
}

function ClientToString() {
    $stok = Plaintext( $this.Token )
    return "Cx1Client connected to $($this.Cx1URL) tenant $($this.Tenant) with token $(shorten $stok)"
}

function Plaintext( $securestring ) {
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securestring);
    $PlainTextString = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr);
    return $PlainTextString
}


function New-Application {
    param (
        [Parameter(Mandatory=$true)][string]$name,
        [Parameter(Mandatory=$false)][int]$criticality = 3
    )
    
    $params = @{
        name = $name
        criticality = $criticality
    }

    return $this.Cx1Post( "applications/", $params, "Failed to create application" )
}
function Get-Applications {
    param(
        [Parameter(Mandatory=$false)][int]$limit = 10,
        [Parameter(Mandatory=$false)][string]$name = ""
    )
    $params = @{
        limit = $limit
    }
    if ( $name -ne "" ) { $params.Add( "name", $name ) }
    return $this.Cx1Get("applications/", $params,  "Failed to get applications" )
}
function Remove-Application( $id ) {
    return $this.Cx1Delete( "applications/$id", "Failed to delete application" )
}

function New-Project {
    param (
        [Parameter(Mandatory=$true)][string]$name,
        [Parameter(Mandatory=$false)][int]$criticality = 3
    )
    
    $params = @{
        name = $name
        criticality = $criticality
    }

    return $this.Cx1Post( "projects/", $params, "Failed to create project" )
}
function Get-Projects {
    param(
        [Parameter(Mandatory=$false)][int]$limit = 10,
        [Parameter(Mandatory=$false)][string]$name = ""
    )
    $params = @{
        limit = $limit
    }
    if ( $name -ne "" ) { $params.Add( "name", $name ) }
    return $this.Cx1Get("projects/", $params,  "Failed to get projects" )
}
function Remove-Project( $id ) {
    return $this.Cx1Delete( "projects/$id", "Failed to delete application" )
}

function Get-ProjectConfiguration( $id ) {
	$params = @{
		"project-id" = $id
	}
	return $this.Cx1Get( "configuration/project", $params, "Failed to get project configuration" )
}

function New-ScanGit {
    param(
        [Parameter(Mandatory=$true)][string]$projectID,
        [Parameter(Mandatory=$true)][string]$repo,
        [Parameter(Mandatory=$true)][string]$branch,
        [Parameter(Mandatory=$true)][array]$scanConfig
        
    )

    $body = @{
        project = @{ id = $projectID }
        type = "git"
        handler = @{ 
            repoUrl = $repo
            branch = $branch
        }
    }
    $body['config'] = $scanConfig

    return $this.Cx1Post( "scans/", $body, "failed to trigger scan" )
}
function Get-Scans {
    param(
        [Parameter(Mandatory=$false)][int]$limit = 10,
        [Parameter(Mandatory=$false)][string]$projectID = "",
        [Parameter(Mandatory=$false)][string]$statuses = "",
        [Parameter(Mandatory=$false)][string]$sort = "+created_at",
        [Parameter(Mandatory=$false)][int]$offset = 0
    )
    $params = @{
        sort = $sort
        limit = $limit
        offset = $offset
    }

    if ( $projectID -ne "" ) { $params.Add( "project-id", $projectID ) }
    if ( $statuses -ne "" ) { $params.Add( "statuses", $statuses) }

    return $this.Cx1Get("scans/", $params,  "Failed to get scans" )
}
function Remove-Scan($id) {
    return $this.Cx1Delete("scans/$id",  "Failed to get scans" )
}

function Cancel-Scan($id) {
    $params = @{
        status = "Canceled"
    }
    return $this.Cx1Patch( "scans/$id", $params, "Failed to cancel scan" )
}

function Get-Scan($id) {
    return $this.Cx1Get("scans/$id", @{}, "Failed to get scan" )
} 

function Get-ScanWorkflow($id) {
    return $this.Cx1Get("scans/$id/workflow", @{}, "Failed to get scan workflow" )
} 

function Get-ScanIntegrationsLog($id) {
    return $this.Cx1Get("integrations-logs/$id", @{}, "Failed to get scan integrations log" )
} 

function Get-ScanSASTMetadata($id) {
    return $this.Cx1Get("sast-metadata/$id", @{}, "Failed to get scan sast metadata" )
} 

function Get-ScanSASTEngineLog($id) {
    return $this.Cx1Get("logs/$id/sast", @{}, "Failed to get scan sast enginelogs" )
}

function Get-Results() {
    param(
        [Parameter(Mandatory=$true)][string]$scanID,
        [Parameter(Mandatory=$false)][int]$limit = 10,
        [Parameter(Mandatory=$false)][array]$severity = @(),
        [Parameter(Mandatory=$false)][array]$state = @(),
        [Parameter(Mandatory=$false)][array]$status = @()
    )

    $params = @{
        "scan-id" =  $scanID
		"limit" =    $limit
    }
    if ( $state.Length -gt 0 ) { $params.Add( "state", $state ) }
    if ( $severity.Length -gt 0 ) { $params.Add( "severity", $severity ) }
    if ( $status.Length -gt 0 ) { $params.Add( "status", $status ) }

    return $this.Cx1Get( "results", $params, "Failed to get results" )
}

function Add-ResultPredicate {
    param(
        [Parameter(Mandatory=$true)][string]$simID,
        [Parameter(Mandatory=$true)][string]$projectID,
        [Parameter(Mandatory=$true)][string]$severity, # HIGH, MEDIUM etc
        [Parameter(Mandatory=$true)][string]$state, # TO_VERIFY, CONFIRMED etc
        [Parameter(Mandatory=$false)][string]$comment = ""
    )

    $body = [array]@(@{
        similarityId = $simID
        projectId = $projectID
        comment = $comment
        severity = $severity
        state = $state
    })

    return $this.Cx1Post( "sast-results-predicates/", $body, "failed to add results predicate" )
}

function Get-Presets() {
    param(
        [Parameter(Mandatory=$false)][int]$limit = 10,
        [Parameter(Mandatory=$false)][int]$offset = 0,
        [Parameter(Mandatory=$false)][bool]$exact = $false,
        [Parameter(Mandatory=$false)][bool]$details = $false,
        [Parameter(Mandatory=$false)][string]$name = ""
    )
	$params = @{
		"offset" =  $offset
		"limit" =           $limit
		"exact_match"=     $exact
		"include_details" = $details
	}
    if ( $name -ne "" ) { $params.Add( "name", $name ) }
    return $this.Cx1Get( "presets", $params, "Failed to get presets" )
}

function Get-Audit() {
    param (
        [Parameter(Mandatory=$false)][bool]$download = $false
    )

    $res = $this.Cx1Get( "audit", @{}, "Failed to get Audit" )

    if ( $download ) {
        $events = $res.events

        foreach ( $logfile in $res.links ) {
            $res = req $logfile.url "GET" $this "Failed to download audit json" "" $this.Proxy
            $events += $res
        }
        return $events
    } else {
        return $res.events
    }
}

function Set-ShowErrors( $show ) {
    $this.ShowErrors = $show
}

function Get-Users() {
    param (
        [Parameter(Mandatory=$false)][string]$userEmail = ""
    )
    $params = @{}
    if ( $userEmail -ne "" ) {
        $params.Add( "email", $userEmail )
    }
    return $this.IAMGet( "auth/admin", "users", $params, "Error getting list of users (optional email = $userEmail)" )
}

function Get-UserByEmail() {
    param (
        [Parameter(Mandatory=$true)][string]$userEmail
    )
    $params = @{}
    $params.Add( "email", $userEmail )
    return $this.IAMGet( "auth/admin", "users", $params, "Error getting users with email = $userEmail" )
}
function Get-UserByID() {
    param (
        [Parameter(Mandatory=$true)][string]$userID
    )
    return $this.IAMGet( "auth/admin", "users/$userID", $params, "Error getting info for user $userID" )
}

function Get-UserGroups() {
    param (
        [Parameter(Mandatory=$true)][string]$userID
    )

    return $this.IAMGet( "auth/admin", "users/$userID/groups", @{}, "Error getting a list of groups assigned to user $userID" )
}

function Get-Groups() {
    param (
        [Parameter(Mandatory=$false)][string]$search = ""
    )

    $params = @{}
    if ( $search -ne "" ) {
        $params.Add( "search", $search )
    }

    return $this.IAMGet( "auth/admin", "groups", $params, "Error getting a list of groups (optional search: $search)" )
}

function Get-GroupByName() {
    param (
        [Parameter(Mandatory=$true)][string]$search
    )
    $groups = $this.GetGroups( $search )    
    return FindGroupInHierarchy $groups $search 
}

function Get-GroupRoles() {
    param (
        [Parameter(Mandatory=$true)][string]$groupID
    )
    $group = $this.IAMGet( "auth/admin", "groups/$groupID", @{}, "Error getting details for group ID $groupID" )
    $roles = [array]@()
    # in a group the roles are just names, not the actual role object
    foreach ( $iamrole in $group.realmRoles ) {
        $role = $this.GetIAMRoleByName( $iamrole )
        $roles += $this.GetDecomposedRoles( $role.id )
    } 

    foreach ( $client in ($group.clientRoles.psobject.Members | where-object membertype -like 'noteproperty') ) {
        $clientID = $this.GetClients( $client.Name )
        
        foreach ( $approle in $client.Value ) {
                        $role = $this.GetClientRoleByName( $clientID.id, $approle )
            $roles += $role
            if ( $role.composite ) {
                $roles += $this.GetDecomposedRoles( $role.id )
            }
        }
    }


    return $roles
    
}

function Get-IAMRoles() {
    return $this.IAMGet( "auth/admin", "roles", @{}, "Error getting list of IAM Roles" )
}
function Get-ClientRoles() {
    param (
        [Parameter(Mandatory=$true)][string]$clientID
    )
    return $this.IAMGet( "auth/admin", "clients/$clientID/roles", @{}, "Error getting list of Client Roles under client $clientID" )
}
function Get-ClientRoleByName() {
    param (
        [Parameter(Mandatory=$true)][string]$clientID,
        [Parameter(Mandatory=$true)][string]$roleName
    )
    return $this.IAMGet( "auth/admin", "clients/$clientID/roles/$roleName", @{}, "Error getting Client Role named $roleName under client $clientID" )
}

function Get-IAMRoleByName() {
    param (
        [Parameter(Mandatory=$true)][string]$roleName
    )

    return $this.IAMGet( "auth/admin", "roles/$roleName", @{}, "Error getting role by name $roleName" )
}
function Get-RoleComposites() {
    param (
        [Parameter(Mandatory=$true)][string]$roleID
    )
    return $this.IAMGet( "auth/admin", "roles-by-id/$roleID/composites", @{}, "Error getting role composites for role $roleID" )
}
function Get-Clients() {
    param (
        [Parameter(Mandatory=$false)][string]$clientID = ""
    )

    $params = @{}
    if ( -Not $clientID -eq "" ) {
        $params.Add("clientId", $clientID)
    }
    return $this.IAMGet( "auth/admin", "clients", $params, "Failed to get clients (client id: $clientID)" )
}

function Get-RoleMappings() {
    param (
        [Parameter(Mandatory=$false)][string]$userID = ""
    )

    return $this.IAMGet( "auth/admin", "users/$userID/role-mappings/", @{}, "Failed to get role mappings for userID $userID" )
}

function Get-ResourceEntityAssignment() {
    param (
        [Parameter(Mandatory=$true)][string]$resourceID,
        [Parameter(Mandatory=$true)][string]$entityID
    )

    $params = @{
        "entity-id" = $entityID
        "resource-id" = $resourceID
    }

    return $this.Cx1Get( "access-management", $params, "Failed to get access assignment between entity $entityID and resource $resourceID" )
}

function Get-ResourcesAccessibleToEntity() {
    param (
        [Parameter(Mandatory=$true)][string]$entityID,
        [Parameter(Mandatory=$false)][string]$entityType = "user",
        [Parameter(Mandatory=$false)][string]$resourceTypes = "tenant,application,project"
    )
    $params = @{
        "entity-id" = $entityID
        "entity-type" = $entityType
        "resource-types" = $resourceTypes
    }
    return $this.Cx1Get( "access-management/resources-for", $params, "Failed to get $resourceTypes resources accessible to $entityType $entityID" )
}

function Get-Flags() {
    $params = @{
        filter = $this.TenantID
    }
    return $this.Cx1Get( "flags", $params, "Failed to get flags for tenant $($this.TenantID)" )
}
function Get-TenantInfo() {
    return $this.IAMGet( "auth/admin", "", @{}, "Failed to get tenant info" )
}

###########################
# API-calls above this line
###########################

function NewCx1Client( $cx1url, $iamurl, $tenant, $apikey, $proxy ) {
    try  {
        $client = [PSCustomObject]@{
            Cx1URL = $cx1url
            IAMURL = $iamurl
            Tenant = $tenant
            TenantID = ""
            APIKey = ConvertTo-SecureString $apikey -AsPlainText -Force 
            Token = (New-Object System.Security.SecureString)
            Proxy = $proxy
            Expiry = (Get-Date)
            ShowErrors = $true
        }

        if ( $proxy -ne "" ) {
            if ($PSVersionTable.PSEdition -eq 'Core') {
                $Script:PSDefaultParameterValues = @{
                    "invoke-restmethod:SkipCertificateCheck" = $true
                    "invoke-webrequest:SkipCertificateCheck" = $true
                }
            } else {
                Add-Type @"
                    using System.Net;
                    using System.Security.Cryptography.X509Certificates;
                    public class TrustAllCertsPolicy : ICertificatePolicy {
                        public bool CheckValidationResult(
                            ServicePoint srvPoint, X509Certificate certificate,
                            WebRequest request, int certificateProblem) {
                            return true;
                        }
                    }
"@
            
                [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
            }
        }

        $client | Add-Member ScriptMethod -name "GetToken" -Value ${function:GetToken} -Force
        $client | Add-Member ScriptMethod -name "ToString" -Value ${function:ClientToString} -Force
        $client | Add-Member ScriptMethod -name "Cx1Get" -Value ${function:Cx1Get}
        $client | Add-Member ScriptMethod -name "Cx1Delete" -Value ${function:Cx1Delete}
        $client | Add-Member ScriptMethod -name "Cx1Post" -Value ${function:Cx1Post}
        $client | Add-Member ScriptMethod -name "Cx1Patch" -Value ${function:Cx1Patch}
        $client | Add-Member ScriptMethod -name "IAMGet" -Value ${function:IAMGet}

        $client | Add-Member ScriptMethod -name "CreateApplication" -Value ${function:New-Application}
        $client | Add-Member ScriptMethod -name "GetApplications" -Value ${function:Get-Applications}
        $client | Add-Member ScriptMethod -name "DeleteApplication" -Value ${function:Remove-Application}
        
        $client | Add-Member ScriptMethod -name "CreateProject" -Value ${function:New-Project}
        $client | Add-Member ScriptMethod -name "GetProjects" -Value ${function:Get-Projects}
        $client | Add-Member ScriptMethod -name "DeleteProject" -Value ${function:Remove-Project}
        $client | Add-Member ScriptMethod -name "GetProjectConfiguration" -Value ${function:Get-ProjectConfiguration}
        $client | Add-Member ScriptMethod -name "GetPresets" -Value ${function:Get-Presets}
        

        $client | Add-Member ScriptMethod -name "RunGitScan" -Value ${function:New-ScanGit}
        $client | Add-Member ScriptMethod -name "GetScans" -Value ${function:Get-Scans}
        $client | Add-Member ScriptMethod -name "GetScan" -Value ${function:Get-Scan}
        $client | Add-Member ScriptMethod -name "DeleteScan" -Value ${function:Remove-Scan}
        $client | Add-Member ScriptMethod -name "CancelScan" -Value ${function:Cancel-Scan}        

        $client | Add-Member ScriptMethod -name "GetScanWorkflow" -Value ${function:Get-ScanWorkflow}
        $client | Add-Member ScriptMethod -name "GetScanIntegrationsLog" -Value ${function:Get-ScanIntegrationsLog}
        $client | Add-Member ScriptMethod -name "GetScanSASTMetadata" -Value ${function:Get-ScanSASTMetadata}
        $client | Add-Member ScriptMethod -name "GetScanSASTEngineLog" -Value ${function:Get-ScanSASTEngineLog}        
        $client | Add-Member ScriptMethod -name "GetScanInfo" -Value ${function:Get-ScanInfo}

        $client | Add-Member ScriptMethod -name "GetResults" -Value ${function:Get-Results}
        $client | Add-Member ScriptMethod -name "AddResultPredicate" -Value ${function:Add-ResultPredicate}

        $client | Add-Member ScriptMethod -name "SetShowErrors" -Value ${function:Set-ShowErrors}

        $client | Add-Member ScriptMethod -name "GetAudit" -Value ${function:Get-Audit}

        $client | Add-Member ScriptMethod -name "GetUsers" -Value ${function:Get-Users}
        $client | Add-Member ScriptMethod -name "GetUserByEmail" -Value ${function:Get-UserByEmail}
        $client | Add-Member ScriptMethod -name "GetUserByID" -Value ${function:Get-UserByID}
        
        $client | Add-Member ScriptMethod -name "GetUserGroups" -Value ${function:Get-UserGroups}
        $client | Add-Member ScriptMethod -name "GetUserInheritedGroups" -Value ${function:Get-UserInheritedGroups}
        $client | Add-Member ScriptMethod -name "GetGroupsFlat" -Value ${function:Get-GroupsFlat}
        $client | Add-Member ScriptMethod -name "GetGroups" -Value ${function:Get-Groups}
        $client | Add-Member ScriptMethod -name "GetGroupByName" -Value ${function:Get-GroupByName}
        
        $client | Add-Member ScriptMethod -name "GetClients" -Value ${function:Get-Clients}
        $client | Add-Member ScriptMethod -name "GetIAMRoles" -Value ${function:Get-IAMRoles}
        $client | Add-Member ScriptMethod -name "GetClientRoles" -Value ${function:Get-ClientRoles}
        $client | Add-Member ScriptMethod -name "GetGroupRoles" -Value ${function:Get-GroupRoles}
        $client | Add-Member ScriptMethod -name "GetRoleComposites" -Value ${function:Get-RoleComposites}
        $client | Add-Member ScriptMethod -name "GetRoleMappings" -Value ${function:Get-RoleMappings}
        $client | Add-Member ScriptMethod -name "GetIAMRoleByName" -Value ${function:Get-IAMRoleByName}
        $client | Add-Member ScriptMethod -name "GetClientRoleByName" -Value ${function:Get-ClientRoleByName}
        
        $client | Add-Member ScriptMethod -name "GetDecomposedRoles" -Value ${function:Get-DecomposedRoles}
        $client | Add-Member ScriptMethod -name "GetUserPermissions" -Value ${function:Get-UserPermissions}

        $client | Add-Member ScriptMethod -name "GetResourceEntityAssignment" -Value ${function:Get-ResourceEntityAssignment}
        $client | Add-Member ScriptMethod -name "GetResourcesAccessibleToEntity" -Value ${function:Get-ResourcesAccessibleToEntity}

        $client | Add-Member ScriptMethod -name "GetFlags" -Value ${function:Get-Flags}
        $client | Add-Member ScriptMethod -name "GetTenantInfo" -Value ${function:Get-TenantInfo}

        $client | Add-Member ScriptMethod -name "ArrayContainsRole" -Value ${function:ArrayContainsRole}
        

        $client.GetToken()
        $client.TenantID = $client.GetTenantInfo().id

        return $client
    } catch {
        log $_
    }
}

########################
# Convenience functions below
########################

$stages = @( "Queued", "Running", "SourcePulling", "ScanQueued", "ScanStart", "ScanEnd" )

$regex = @{
    Queued = "reached, scan queued"    
    Running = "Scan running"
    SourcePulling = "fetch-sources-.* started"
    ScanQueued = "Queued in sast resource manager"
    ScanStart = "sast-worker-.* started"
    ScanEnd = "sast-worker-.* ended"
}

function Get-ScanInfo( $scan ) {
    $startTime = $scan.createdAt.ToLocalTime()

    $scanInfo = [PSCustomObject]@{
        ProjectID = ""
        ProjectName = ""
        ScanID = ""
        Status = ""
        FailReason = ""
        LOC = 0
        FileCount = 0
        Incremental = $false
        Preset = ""
        Start = $startTime
        Queued = $null #"Max concurent scans reached, scan queued (Position: 40)"
        Running = $null #"Scan running"
        SourcePulling = $null #"fetch-sources-frankfurt started"
        ScanQueued = $null #"sast-rm-frankfurt Queued in sast resource manager"
        ScanStart = $null #"sast-worker-frankfurt started"
        ScanEnd = $null #"sast-worker-frankfurt ended"
        Finish = $null #"Scan Completed"
    }

    try {
        $workflow = $this.GetScanWorkflow($scan.id)
        foreach( $log in $workflow ) {
            if ( $log.Timestamp -is [string] ) {
                $log.Timestamp = [datetime]::Parse( $log.Timestamp )
            }
            $log.Timestamp = $log.Timestamp.ToLocalTime()
            $lastStage = "Start"
            foreach( $stage in $stages ) {
                if ( $log.Info -match $regex[$stage] ) {
                    $scanInfo.$stage = $log.Timestamp
    
                    if ( $null -eq $scaninfo.$lastStage ) {
                        $scanInfo.$lastStage = $scanInfo.$stage
                    }
    
                    break
                }            
    
                $lastStage = $stage
            }        
        }
    } catch {
        Write-Warning "Failed to get workflow for scan $($scan.id): $_"
    }


    try {
        $metadata = $this.GetScanSASTMetadata( $scan.id )
        $scanInfo.LOC = $metadata.loc
        $scanInfo.FileCount = $metadata.fileCount
        $scanInfo.Incremental = $metadata.isIncremental
        $scanInfo.Preset = $metadata.queryPreset
    } catch {
        Write-Warning "Failed to get metadata for scan $($scan.id): $_"
    }
    
    if ( $scan.status -eq "Failed" ) {
        $scanInfo.FailReason = "zeebe" # default fail reason
        if ( $null -ne $scan.statusDetails ) {
            foreach ( $reason in $scan.statusDetails ) {
                if ( $reason.name -eq "sast" ) {
                    if ( $reason.status -eq "failed" ) {
                        $scanInfo.FailReason = $reason.details
                    }
                }
            }
        }
    }

    $scanInfo.ProjectID = $scan.projectId
    $scanInfo.ProjectName = $scan.projectName
    $scanInfo.ScanID = $scan.id
    $scanInfo.Status = $scan.status
    $scanInfo.Finish = $scan.updatedAt.ToLocalTime()
    return $scanInfo
}


function Get-UserPermissions() {
    param (
        [Parameter(Mandatory=$true)][string]$userID
    )

    $mappings = $this.GetRoleMappings( $userID )

    $comproles = [array]@()
    $roles = [array]@()

    foreach ( $iamrole in $mappings.realmMappings ) {
        if ( -Not(ArrayContainsRole $roles $iamrole) ) {
            if ( $iamrole.composite ) {
                $comproles += $iamrole
            } else {
                $roles += $iamrole                
            }
        }
    } 

    foreach ( $client in ($mappings.clientMappings.psobject.Members | where-object membertype -like 'noteproperty') ) {
        $client = $client.Value
        foreach ( $crole in $client.mappings ) {
            if ( -Not(ArrayContainsRole $roles $crole) ) {
                if ( $crole.composite ) {
                    $comproles += $crole
                } else {
                    $roles += $crole
                }
            }
        }
    }

    foreach ( $comprole in $comproles ) {
        if ( -Not(ArrayContainsRole $roles $comprole) ) {
            $roles += $comprole
            $subroles = $this.GetDecomposedRoles( $comprole.id )
            foreach ( $sr in $subroles ) {
                if ( -Not (ArrayContainsRole $roles $sr) ) {
                    $roles += $sr
                }
            }            
        }
    }

    return $roles
}


function Get-DecomposedRoles() {
    param (
        [Parameter(Mandatory=$true)][string]$roleID
    )

    $subRoles = [array]$this.GetRoleComposites( $roleID )
    $roles = @()

    foreach ( $subrole in $subRoles ) {
        if ( $subrole.composite ) {
            $roles += $this.GetDecomposedRoles( $subrole.id )
        } else {
            $roles += $subrole
        }
    }

    return $roles
}

function ArrayContainsRole( $array, $role ) {
    foreach ( $ar in $array ) {
        if ( $ar.id -eq $role.id ) {
            return $true
        }
    }
    return $false
}

function Get-UserInheritedGroups() {
    param (
        [Parameter(Mandatory=$true)][string]$userID
    )

    $groups = @()
    $direct_groups = $this.GetUserGroups( $userID )
    foreach ( $group in $direct_groups ) {
        $groups += $this.GetGroupsFlat( $group.id )
    }
    return $groups
}
function Get-GroupsFlat() {
    param (
        [Parameter(Mandatory=$true)][string]$groupID
    )

    $group = $this.IAMGet( "auth/admin", "groups/$groupID", @{}, "Error getting group info for group with ID $groupID" )

    if ( $group.path -eq "/$($group.name)" ) { # no parent
        return @( $group )
    } else {
        $groups = @()

        $split_path = $group.path.Split( "/" )
        foreach ( $part in $split_path ) {
            if ( $part -ne "" ) {
                $subgroup = $this.GetGroupByName( $part )
                if ( $null -ne $subgroup ) {
                    $groups += $subgroup
                }
            }
        }

        return $groups
    }
}

function FindGroupInHierarchy( $groups, $target ) {
    foreach ( $group in $groups ) {
        Write-Host " - $($group.name)"
        if ( $group.name -eq $target ) {
            return $group
        } else {
            $subgroup = FindGroupInHierarchy $group.subGroups $target 
            if ( $null -ne $subgroup ) {
                return $subgroup
            }
        }
    }
    return $null
}

function Get-ConfigurationValue( $config, $key ) {
    $config | foreach-object { 
        if ( $_.key -eq $key -or $_.name -eq $key ) {
            return $_.value
        }
    }
    return ""
}



# functions to interact directly with the API will be exposed via the returned client object
Export-ModuleMember -Function NewCx1Client

# convenience functions to do stuff with the returned data will be exposed directly
Export-ModuleMember -Function Get-ConfigurationValue