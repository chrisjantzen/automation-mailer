using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)
Write-Information ("Incoming {0} {1}" -f $Request.Method,$Request.Url)

Function ImmediateFailure ($Message) {
    Write-Error $Message
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        headers    = @{'content-type' = 'application\json' }
        StatusCode = [httpstatuscode]::OK
        Body       = @{"Error" = $Message } | convertto-json
    })
    exit 1
}

##########
# CONSTANTS
##########

$VALID_EMAILS = $Env:VALID_EMAILS -split ','
$VALID_EMAILS = $VALID_EMAILS.Trim()

# Get the sent api key and verify it
$clientToken = $request.headers.'x-api-key'

$ApiKeys = (Get-ChildItem env:APIKey_*)
$ApiKey = $ApiKeys | Where-Object { $_.Value -eq $clientToken }

# Check if the client's API token matches our stored version and that it's not too short.
# Without this check, a misconfigured environmental variable could allow unauthenticated access.
if (!$ApiKey -or $ApiKey.Value.Length -lt 14 -or $clientToken -ne $ApiKey.Value) {
    ImmediateFailure "401 - API token does not match"
}

# Verify against the Organization IP whitelist  (OrgList.csv)
$DISABLE_ORGLIST_CSV = ($Env:DISABLE_ORGLIST_CSV -and (($Env:DISABLE_ORGLIST_CSV).ToLower() -eq 'true'))
If (-not $DISABLE_ORGLIST_CSV) {
    # Get the client's IP address
    $ClientIP = ($request.headers.'X-Forwarded-For' -split ':')[0]
    if (-not $ClientIP -and $request.url.StartsWith("http://localhost:")) {
        $ClientIP = "localtesting"
    }
    # Get the organization associated with the API key
    $ApiKeyOrg = ($ApiKey.Name -split '_')[1]
    # Check the client's IP against the IP/org whitelist.
    if ($ApiKeyOrg -ne 'Global') {
        $OrgList = import-csv ($TriggerMetadata.FunctionDirectory + "\OrgList.csv") -delimiter ","
        $AllowedOrgs = $OrgList | where-object { $_.ip -eq $ClientIP -and ($_.APIKeyName -eq $ApiKeyOrg -or $_.APIKeyName -eq $ApiKey.Name) }
        if (!$AllowedOrgs) { 
            ImmediateFailure "401 - No match found in allowed IPs list"
        }
    }
}

# Verify the email address they are trying to use is valid
if (!$Request.Body.From -or $Request.Body.From -isnot [System.Object] -or !$Request.Body.From.Email) {
    ImmediateFailure "400 - A valid email is required in the From body parameter (object with Email and an optional Name)"
}

$FromEmail = $Request.Body.From.Email
if ($FromEmail -notin $VALID_EMAILS) {
    ImmediateFailure "401 - No match found in allowed email sender list for: $FromEmail"
}

# Get the subject, body, and any attachments and verify the first 2 exist
if (!$Request.Body.Subject -or $Request.Body.Subject -isnot [System.String]) {
    ImmediateFailure "400 - A valid subject is required in the Subject body parameter"
}
$EmailSubject = $Request.Body.Subject

if (!(($Request.Body.TextContent -and $Request.Body.TextContent -is [System.String]) -or ($Request.Body.HTMLContent -and $Request.Body.HTMLContent -is [System.String]))) {
    ImmediateFailure "400 - A valid email body is required in the TextContent or HTMLContent body parameter"
}
$TextContent = $HTMLContent = ""
if ($Request.Body.TextContent -and $Request.Body.TextContent -is [System.String]) {
    $TextContent = $Request.Body.TextContent
} 
if ($Request.Body.HTMLContent -and $Request.Body.HTMLContent -is [System.String]) {
    $HTMLContent = $Request.Body.HTMLContent
}


#######
# Everything looks correct. Lets send the email!
#######

function SanitizeEmailArray($EmailArray) {
    if ($EmailArray -isnot [System.Array]) {
        if ($EmailArray -is [System.Object]) {
            $EmailArray = @($EmailArray)
        } else {
            return @()
        }
    }

    $SantizedEmails = @()
    foreach ($EmailObj in $EmailArray) {
        if (!$EmailObj.Email -or $EmailObj.Email -isnot [System.String]) {
            continue
        }
        $NewEmailObj = @{
            email = $EmailObj.Email
        }
        if ($EmailObj.Name -and $EmailObj.Name -is [System.String]) {
            $NewEmailObj.name = $EmailObj.Name
        }
        $SantizedEmails += $NewEmailObj
    }

    return $SantizedEmails
}

$From = @{
    email = $Request.Body.From.Email
}
if ($Request.Body.From.Name -and $Request.Body.From.Name -is [System.String]) {
    $From.name = $Request.Body.From.Name
}

$To = @()
if ($Request.Body.To) {
    $To = @(SanitizeEmailArray($Request.Body.To))
}

$CcEmail = @()
if ($Request.Body.Cc) {
    $CcEmail = @(SanitizeEmailArray($Request.Body.Cc))
}
$BccEmail = @()
if ($Request.Body.Bcc) {
    $BccEmail = @(SanitizeEmailArray($Request.Body.Bcc))
}

$ReplyTo = @{}
if ($Request.Body.ReplyTo) {
    $ReplyTo = SanitizeEmailArray($Request.Body.ReplyTo) | Select-Object -First 1
}

$Attachments = @()
if ($Request.Body.Attachments) {
    $OriginalAttachments = $Request.Body.Attachments
    if ($OriginalAttachments -isnot [System.Array]) {
        if ($OriginalAttachments -is [System.Object]) {
            $OriginalAttachments = @($OriginalAttachments)
        } else {
            $OriginalAttachments = @()
        }
    }

    $SantizedAttachments = @()
    foreach ($Attachment in $OriginalAttachments) {
        if (!$Attachment.Filename -or $Attachment.Filename -isnot [System.String] -or 
            !$Attachment.ContentType -or $Attachment.ContentType -isnot [System.String] -or 
            !$Attachment.Base64Content -or $Attachment.Base64Content -isnot [System.String]) 
        {
            continue
        }
        $NewAttachmentObj = @{
            filename = $Attachment.Filename
            content = $Attachment.Base64Content
            type = $ContentType
            disposition = "attachment"
        }
        $SantizedAttachments += $NewAttachmentObj
    }
    $Attachments = @($SantizedAttachments)
}

$ContentType = "text/plain"
$Content = $TextContent
if ($HTMLContent) {
    $ContentType = "text/html"
    $Content = $HTMLContent
}
$mailBody = @{
    "personalizations" = @(
        @{
            "to" = $To
            "cc" = $CcEmail
            "bcc" = $BccEmail
        }
    )
    "from" = $From
    "reply_to" = $ReplyTo
    "subject" = $EmailSubject
    "content" = @(
        @{
            "type" = $ContentType
            "value" = $Content
        }
    )
    "attachments" = $Attachments
}

# Remove empty values as they'll break the api call
($mailBody.GetEnumerator() | Where-Object { -not $_.Value -or $_.Value.Count -eq 0 }) | Foreach-Object { 
    $mailBody.Remove($_.Name) 
}

($mailBody.personalizations[0].GetEnumerator() | Where-Object { -not $_.Value -or $_.Value.Count -eq 0 }) | Foreach-Object { 
    $mailBody.personalizations[0].Remove($_.Name) 
}

$mailBody = ConvertTo-Json $mailBody -Depth 10

# Header for SendGrid API
$headers = @{
    'Authorization' = "Bearer $env:SENDGRID_API_KEY"
} 
Write-Host "Sending Email to SendGrid API..."

try {
    Write-Information ("Outgoing {0} {1}" -f $ENV:SENDGRID_API_URL, $mailBody)
    $Response = Invoke-RestMethod -Method Post -Uri $ENV:SENDGRID_API_URL -Body $mailBody -Headers $headers -ContentType application/json
} catch {
    Write-Warning $_.Exception.Message
    $ErrorDetails = $_.ErrorDetails.Message | ConvertFrom-Json
    if ($ErrorDetails.errors) {
        $ErrorDetails = $ErrorDetails.errors | Select-Object -First 1
    }
    Write-Warning "Reason: $($ErrorDetails.message)  Field: $($ErrorDetails.field)  SendGrid Help: $($ErrorDetails.help)"
    ImmediateFailure "$($_.Exception.Response.StatusCode.value__) - Failed to send the email. (Reason: $($ErrorDetails.message)  Field: $($ErrorDetails.field)  SendGrid Help: $($ErrorDetails.help))" 
}

Write-Information $Response
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    headers    = @{'content-type' = 'application\json' }
    StatusCode = [httpstatuscode]::OK
    Body       = ($Response | ConvertTo-Json)
})
