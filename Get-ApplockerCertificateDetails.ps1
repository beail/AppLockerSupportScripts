# This script reads exported AppLocker policies (XML) and searches for Publisher Allow Rules

# Use the -PolicyFile script parameter to point to your exported policy file or use: (Get-ApplockerPolicy -Effective -Xml) on a device running AppLocker

param([Parameter(Mandatory=$True)]
[string]$PolicyFile)

$script:ResultsCollection = @()

Function Get-ApplockerCertificateDetails{
param([string]$policyfile)
    
    $XMLObj = Select-Xml -Path $policyfile -XPath 'AppLockerPolicy'
    
    foreach($item in $XMLObj.Node.ChildNodes)
    {
        
        if($Item.FilePublisherRule.Name -and $item.FilePublisherRule.Action -eq "Allow")
        {
            $AppLockerObject = New-Object -TypeName PSCustomObject
            $AppLockerObject | Add-Member -MemberType NoteProperty -Name RuleName -Value $item.FilePublisherRule.Name-Force
            $AppLockerObject | Add-Member -MemberType NoteProperty -Name RuleType -Value $item.Type -Force

            foreach($rule in $item.FilePublisherRule.conditions.FilePublisherCondition)
            {
                $AppLockerObject | Add-Member -MemberType NoteProperty -Name PublisherName -Value $rule.PublisherName -Force
                $AppLockerObject | Add-Member -MemberType NoteProperty -Name ProductName -Value $rule.ProductName -Force
                $AppLockerObject | Add-Member -MemberType NoteProperty -Name BinaryName -Value $rule.BinaryName -Force
                $AppLockerObject | Add-Member -MemberType NoteProperty -Name BinaryVersionRange -Value ($rule.BinaryVersionRange.LowSection + " > " + $rule.BinaryVersionRange.HighSection) -Force
                $ResultsCollection + $AppLockerObject
            }
        }
    }

$ResultsCollection | Out-GridView # ft -AutoSize -Force
}

Get-ApplockerCertificateDetails -policyfile $PolicyFile