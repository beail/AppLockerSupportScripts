# This script searches for files that are support by Microsoft Applocker for SignerCertificate properties

# Use the -SearchPath script parameter to point to your directory to search for files with SignerCertificates

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]
    $SearchPath
)

$script:ResultsCollection = @()

$ApplockerFileTypes = '*.dll','*.exe','*.ocx',"*.com","*.msp","*.msi","*.js","*.ps1","*.vbs"# ,"*.bat","*.cmd" cannot be signed


$FilesFound = Get-ChildItem -Path $SearchPath -Recurse -Include $ApplockerFileTypes
foreach($File in $FilesFound)
    {
        $AppLockerObject = New-Object -TypeName PSCustomObject
        $AppLockerObject | Add-Member -MemberType NoteProperty -Name FullName -Value $File.FullName -Force

        if($null -eq (Get-AuthenticodeSignature -FilePath $file.FullName).SignerCertificate)
        {
            $AppLockerObject | Add-Member -MemberType NoteProperty -Name SignerCertificate -Value "-- unsigned --" -Force
        }
        else
        {
            $AppLockerObject | Add-Member -MemberType NoteProperty -Name SignerCertificate -Value ((Get-AuthenticodeSignature -FilePath $file).SignerCertificate.IssuerName.Name) -Force           $AppLockerObject | Add-Member -MemberType NoteProperty -Name Thumbprint -Value ((Get-AuthenticodeSignature -FilePath $file).SignerCertificate.Thumbprint) -Force
        }   
        $ResultsCollection + $AppLockerObject
    } 

    $ResultsCollection | Out-GridView 