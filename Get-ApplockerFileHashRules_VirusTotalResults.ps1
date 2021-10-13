# This script reads exported AppLocker policies (XML) and searches for Allowed FileHashRules - These file hashes are then queried against VirusTotal APIs for detections
# Usage: 
# Use the $VTApiKey variable to provide your VirusTotal Total API key
# Use the -PolicyFile script parameter to point to your exported policy file

param([Parameter(Mandatory=$true)]
[string]$PolicyFile)

$script:VTApiKey = "9b8de807b934cd5af10d17cf0eb20f001b6992d20a9a2cd875d1b2d5f3ec2a66"
$script:ResultsCollection = @()

Function Get-ApplockerHashRuleDetails{
param([string]$policyfile)
    $XMLObj = Select-Xml -LiteralPath $policyfile -XPath 'AppLockerPolicy'
    
    foreach($item in $XMLObj.Node.ChildNodes.FileHashRule)
    {
        if($Item.Name -and $item.Action -eq "Allow")
        {
            foreach($hash in $item.conditions.filehashcondition.filehash)
            {
                Write-Host "Processing" $item.Name -ForegroundColor Yellow 
                $AppLockerObject = New-Object -TypeName PSObject
                $AppLockerObject | Add-Member -MemberType NoteProperty -Name RuleName -Value $item.Name -Force
                $AppLockerObject | Add-Member -MemberType NoteProperty -Name RuleType -Value $hash.type -Force
                $AppLockerObject | Add-Member -MemberType NoteProperty -Name RuleFileName -Value $hash.sourcefilename -Force
                $AppLockerObject | Add-Member -MemberType NoteProperty -Name RuleHash -Value $hash.data -Force
                $AppLockerObject | Add-Member -MemberType NoteProperty -Name VTResult -Value (Get-VTHashResults -hash ($hash.data).substring(2)) -Force
                $AppLockerObject
                $ResultsCollection += $AppLockerObject
            }
        }
    }

$ResultsCollection | ft -AutoSize -Force
}

Function Get-VTHashResults{
param([Parameter(Mandatory = $True)][string]$hash)    
        $APIRequestURL = "https://www.virustotal.com/vtapi/v2/file/report"
    
        # VT submission
        function Convert-HTTP2JSON($APIRequestURL,$parameters){ 
            $http_request = New-Object -ComObject Msxml2.XMLHTTP 
            $http_request.open("POST", $APIRequestURL, $false) 
            $http_request.setRequestHeader("Content-type","application/x-www-form-urlencoded") 
            $http_request.setRequestHeader("Content-length", $parameters.length); 
            $http_request.setRequestHeader("Connection", "close") 
            try
            {
                $http_request.send($parameters) 
                $script:result = $http_request.responseText
            }
            catch 
            {
                $script:result = "Fail"
            }

        }
        
        Convert-HTTP2JSON $APIRequestURL "resource=$hash&apikey=$VTApiKey"
        
        if(!($result -eq "Fail"))
        {

            # VT response to PSobject
            [System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions") | Out-Null
            $Serialize = New-Object System.Web.Script.Serialization.JavaScriptSerializer
            $Response = $Serialize.DeserializeObject($result)
    
            # Hash not found
            if($Response.verbose_msg -Like '*not among*')
            {
                Return "Unknown Hash"
            }
        
            # Hash found 
            else
            {
                [string]$outputPositives = $Response.positives
                [string]$outputTotal = $Response.total
                Return($outputPositives+"/"+$outputTotal)
            }
        }
        else
        {
            return "API Rejected - Check your VT Key or API limit"
        }

    }


Get-ApplockerHashRuleDetails -policyfile $PolicyFile  

