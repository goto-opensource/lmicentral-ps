class LMICentralError : System.Exception {
    $Status
    $Details

    LMICentralError($Status, $Details) {
        $this.Status = $Status
        $this.Details = $Details
    }

    [string]ToString() {
        return ("LMICentralError({0}|{1})" -f $this.Status, $this.Details)
    }
}


function Build-Uri {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Scope='Function')]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Uri,
        [Parameter(Mandatory=$false)]
        [hashtable]$QueryParameters
    )

    Add-Type -AssemblyName System.Web

    $local:Parameters = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

    if ($QueryParameters) {
        foreach ($local:Param in $QueryParameters.GetEnumerator()) {
            $local:Parameters[$Param.Name] = $local:Param.Value
        }
    }
    $local:Request = [System.UriBuilder]$Uri
    $local:Request.Query = $local:Parameters.ToString()

    $local:Request.Uri.AbsoluteUri
}

function Get-CentralDomain {
    if (Test-Path variable:global:CentralDomain) {
        $local:CentralDomain = Get-Variable -Name CentralDomain -Scope Global -ValueOnly
    } else {
        $local:CentralDomain = 'secure.logmein.com'
    }

    if (Test-Path variable:global:CentralLoginDomain) {
        $local:LoginDomain = Get-Variable -Name CentralLoginDomain -Scope Global -ValueOnly
    } else {
        $local:LoginDomain = 'accounts.logme.in'
    }
    $local:CentralDomain
    $local:LoginDomain
}

function Connect-LMICentral {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Scope='Function')]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory=$true)]
        [pscredential]$Credential,
        [Parameter(Mandatory=$false)]
        [Switch]$NoSessionVariable=$false
    )

    $CentralDomain, $LoginDomain = Get-CentralDomain

    Write-Verbose "Get CSRF token from $LoginDomain"
    $local:LoginResponse = Invoke-WebRequest -SessionVariable LoginSession -Uri "https://$LoginDomain/login.aspx"
    $local:CSRFToken = ($LoginSession.Cookies.GetCookies("https://$LoginDomain") | Where-Object {$_.Name -eq "csrftoken"}).Value

    if ($local:LoginResponse.StatusCode -ne 200) {
        Write-Error "Login service is not available; $LoginDomain $local:LoginResponse.StatusCode"
        throw [LMICentralError]::new($local:LoginResponse.StatusCode, $null)
    }

    $local:LoginParams = @{
        loginattempts = "1"
        clusterid = "10"
        returnurl = "https://$CentralDomain/federated/loginsso.aspx"
        headerframe = "https://$CentralDomain/federated/resources/headerframe.aspx"
        productframe = "https://$CentralDomain/common/pages/cls/login.aspx"
        lang = "en-US"
        regtype = "R"
        trackingproducttype = "2"
        trackinguniqueid = (New-Guid).Guid
        skin = "logmein"
    }

    $local:PasswordPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password))

    $local:LoginForm = @{
        email = $Credential.Username
        password = $local:PasswordPlainText
        csrftoken = $local:CSRFToken
        hiddenEmail = ""
    }

    Write-Verbose "Authenticating at $LoginDomain"
    $local:AuthResponse = Invoke-WebRequest -WebSession $LoginSession -Uri (Build-Uri "https://$LoginDomain/auth.aspx" $local:LoginParams) -Body $local:LoginForm -Method Post -ContentType "application/x-www-form-urlencoded"

    if ($local:AuthResponse.StatusCode -eq 200) {
        Write-Host "Login Successful."

        $local:CentralSession = @{
            logmeinsession = ($LoginSession.Cookies.GetCookies("https://$CentralDomain") | Where-Object {$_.Name -eq "logmeinsession"}).Value
            xsrftoken = ($LoginSession.Cookies.GetCookies("https://$CentralDomain") | Where-Object {$_.Name -eq "XSRF-TOKEN"}).Value
        }

        if ($NoSessionVariable) {
            $local:CentralSession
        } else {
            Set-Variable -Name "LMICentralSession" -Scope Global -Value $local:CentralSession
        }
    } else {
        Write-Host "Login Failed."
    }
}

function Disconnect-LMICentral {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Scope='Function')]
    [CmdletBinding()]
    param ()

    $CentralDomain, $LoginDomain = Get-CentralDomain

    $local:LogoutParams = @{
        clusterid = "10"
        returnurl = "https://$CentralDomain/federated/loginsso.aspx"
        headerframe = "https://$CentralDomain/federated/resources/headerframe.aspx"
        productframe = "https://$CentralDomain/common/pages/cls/login.aspx"
        lang = "en-US"
        skin = "logmein"
        regtype = "R"
        trackingproducttype = "2"
        trackinguniqueid = (New-Guid).Guid
    }

    $local:Cookie = New-Object System.Net.Cookie
    $local:Cookie.Name = 'logmeinsession'
    $local:Cookie.Value = $local:LMICentralSession.logmeinsession
    $local:Cookie.Domain = $local:CentralDomain
    $local:WebSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $local:WebSession.Cookies.Add($local:Cookie)

    $local:LogoutResponse = Invoke-WebRequest -Uri (Build-Uri "https://$LoginDomain/logout.aspx" $local:LogoutParams) -WebSession $local:WebSession

    if ($local:LogoutResponse.StatusCode -eq 200) {
        Write-Host "Logged out from Central."
    } else {
        Write-Host "Failed logging out from Central, cleaning up local session; StatusCode=$local:LogoutResponse.StatusCode"
    }

    Set-Variable -Name "LMICentralSession" -Scope Global -Value $null
}

function Out-LMICentralException {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [object]
        $Exception
    )

    $local:Reader = New-Object System.IO.StreamReader($Exception.Response.GetResponseStream())
    $local:ErrorType = $Exception.Response.ContentType
    $local:Reader.BaseStream.Position = 0
    $local:Reader.DiscardBufferedData()
    $local:ErrorBody = $local:Reader.ReadToEnd()
    $local:Reader.Dispose()

    if ($local:ErrorType -ccontains 'application/json') {
        $local:ErrorJson = ($local:ErrorBody | ConvertFrom-Json)
    }

    if ($Exception.Response.StatusCode -eq 400) {
        $local:Details = ($local:ErrorJson).Details
        Write-Error "Error occured during request; $local:Details"
    }

    if ($Exception.Response.StatusCode -eq 401) {
        Write-Error "LMI Central Session has expired, call Connect-LMICentral to login again"
    }

    throw [LMICentralError]::new($Exception.Response.StatusCode, $local:ErrorJson)
}

function Invoke-LMICentralMethod {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Scope='Function')]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$RelativeUrl,
        [Parameter(Mandatory=$false, Position=1)]
        [Object]$Body=@{},
        [Parameter(Mandatory=$false)]
        [Object]$Session,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Get","Put","Post","Delete", IgnoreCase=$true)]
        [string]$Method="Post"
    )

    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:CentralDomain = (Get-CentralDomain)[0]

    if (-not $Session) {
        Write-Verbose "No Session parameter is specifed using global LMI Central Session"
        $local:LMICentralSession = $Global:LMICentralSession
    } else {
        Write-Verbose "Using Session from parameter"
        $local:LMICentralSession = $Session
    }

    if (-not $local:LMICentralSession) {
        throw "No existing session, call Connect-LMICentral or pass Session parameter!"
    }

    $local:Headers = @{
        "X-XSRF-TOKEN" = $local:LMICentralSession.xsrftoken
    }

    $local:Cookie = New-Object System.Net.Cookie
    $local:Cookie.Name = 'logmeinsession'
    $local:Cookie.Value = $local:LMICentralSession.logmeinsession
    $local:Cookie.Domain = $local:CentralDomain
    $local:WebSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $local:WebSession.Cookies.Add($local:Cookie)
    $local:Body = (ConvertTo-Json -InputObject $Body -Depth 10)

    $local:Url = "https://$local:CentralDomain$RelativeUrl"

    Write-Verbose "--- REQUEST ---"
    Write-Verbose "Body=$local:Body"

    try {
        if ($Method -eq 'GET') {
            Invoke-RestMethod -Method $Method -Headers $local:Headers -Uri $local:Url -WebSession $local:WebSession
        } else {
            Invoke-RestMethod -Method $Method -Headers $local:Headers -Uri $local:Url -Body $local:Body -ContentType 'application/json' -WebSession $local:WebSession
        }
    } catch {
        Out-LMICentralException $_.Exception
    }
}

function Get-LMICentralCommand {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,Position=0)]
        [string]$Criteria1,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$Criteria2,
        [Parameter(Mandatory=$false,Position=2)]
        [string]$Criteria3
    )

    $local:Commands = (Get-Command -Module 'lmicentral-ps' -ListImported)
    if ($Criteria1) { $local:Commands = ($local:Commands | Where-Object { $_.Name -match $Criteria1 }) }
    if ($Criteria2) { $local:Commands = ($local:Commands | Where-Object { $_.Name -match $Criteria2 }) }
    if ($Criteria3) { $local:Commands = ($local:Commands | Where-Object { $_.Name -match $Criteria3 }) }

    $local:Commands
}
