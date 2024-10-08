# automation-mailer
This is a secure email forwarder for STS automation jobs. It requires an API key per-company and can be linked into by automated scripts. 
The script is meant to be deployed to Azure as a function via VS Code and the Azure extension. 

To setup, add your Sendgrid api key and individual api company api keys to the local settings environment variables. 
The company api keys can be in any format you want, I personally used UUID's, but must be greater than 14 characters in length. The name for each companies API key should be in the format `"APIKey_Company"` where `Company` is an acronym or name for that company.

There is also an IP whitelist that whitelists individual company API key's to certain IPs. You can add these in the `OrgList.csv` file. These should be in the format `127.0.0.1,STS` where the second value (in this case STS) is the acronym or name of the company used in the APIKey name.

Push all of this to an Azure function and then you will be able to use the Automation Mailer in your automated scripts. You can send it an email along with the API key and it will send the email using Sendgrid.

Note that you can only send from a set of whitelisted emails. These can be found in `run.ps1`. 

To send an email you must send the following info in the request body in JSON (case-sensitive):
- `From` - An array of emails, each with the format:
  - `Email` - The email to send this from
  - `Name` - An optional From name
- `Subject` - The email subject
- `TextContent` or `HTMLContent` - The content of the email. If using TextContent it will not be encoded as HTML.

The following request body fields can also be used but are optional (case-sensitive):
- `To` - An array of emails, each with the format:
  - `Email` - The email to send to
  - `Name` - An optional To name
- `CC` - Emails to CC. Same format as To
- `BCC` - Emails to BCC. Same format as To
- `ReplyTo` - A reply to email. Same format as To
- `Attachments` - An array of attachments, each with the format:
  - `Filename`
  - `ContentType` - The MIME type of this file
  - `Base64Content` - The attachment encoded in base 64

The following header is also required:
- `x-api-key` - The API key unique to that company. You will also need to ensure you are sending from an IP that is whitelisted for that api key.



Powershell Example:
```powershell
$Email_APIKey = @{
	Url = "AZURE URL"
	Key = "KEY_HERE"
}

$EmailFrom = @{
	Email = 'device.audit@sts.com'
	Name = "Device Audit"
}

$EmailTo_BillingUpdate = @(
	@{
		Email = 'billing@sts.com'
		Name = "Billing"
	}
)

$FileName = "$($Company_Acronym)--Device_List--$($MonthName)_$Year.xlsx"
$Path = $PSScriptRoot + "\$FileName"
$ReportEncoded = [System.Convert]::ToBase64String([IO.File]::ReadAllBytes($Path))

# Send email
$mailbody = @{
	"From" = $EmailFrom
	"To" = $EmailTo_BillingUpdate
	"Subject" = "Bill Needs Updating"
	"HTMLContent" = $HTMLEmail
	"Attachments" = @(
		@{
			Base64Content = $ReportEncoded
			Filename = $FileName
			ContentType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
		}
	)
} | ConvertTo-Json -Depth 6

$headers = @{
	'x-api-key' = $Email_APIKey.Key
}

Invoke-RestMethod -Method Post -Uri $Email_APIKey.Url -Body $mailbody -Headers $headers -ContentType application/json
```