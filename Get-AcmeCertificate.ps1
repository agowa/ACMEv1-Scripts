# Copyright 2017 Klaus Frank
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# Schedule this script to run every 60 Days, so your first Certificate is 2/3 over.
# This way you will have 30 days to react, if the auto renewal fails e. g. because of missing network connectivity
# 
# NOTE: Edit the lines bellow as needed
#-------------------------------------
$MyMailAddress = "webmaster@contoso.com"
$CN = "mail.contoso.com"
$SANs = @(
    "autodiscover.contoso.com",
    "mx01.contoso.com"
);
$CertPath = "c:\Certificates";
$AuthPath = "C:\inetpub\wwwroot\.well-known";
$CertAlias = "$($CN)_$($(get-date -format yyyy-MM-dd-HH-mm))";
$PfxFilePath = "$($CertPath)\$($CertAlias).pfx";
Start-Transcript -Path "$($CertPath)\LetsEncrypt.log" -Force;

$invokeLocation = Get-Location;
try {
    Import-Module ACMESharp -ErrorAction Stop;
} catch [System.IO.FileNotFoundException] {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force;
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted;
    Install-Module -Name ACMESharp -Scope CurrentUser;
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Untrusted;
    Import-Module ACMESharp -ErrorAction Stop;
};
Import-Module WebAdministration;
$MyACMEVault = Get-ACMEVault;

function Register-FQDN {
    param(
        [String]$FQDN
    );
    Write-Debug "New-ACMEIdentifier";
    New-ACMEIdentifier -Dns $FQDN -Alias $FQDN | select status, Expires;
    Write-Debug "Complete-ACMEChallenge";
    Complete-ACMEChallenge $FQDN -ChallengeType http-01 -Handler iis -HandlerParameters @{ WebSiteRef = 'Default Web Site' } | select Identifier, status, Expires;
    Write-Debug "Submit-ACMEChallenge";
    Submit-ACMEChallenge $FQDN -ChallengeType http-01 | select Identifier, status, Expires;

    while ($Auth -ne "valid") {
        $Auth = ((Update-ACMEIdentifier $FQDN -ChallengeType http-01).Challenges | Where-Object {$_.Type -eq "http-01"}).status;
        if($Auth -eq "invalid") {
            Write-Error "ACME Verifidation failed" -Category AuthenticationError;
            break;
        };
        Write-Debug "Waiting for verifidation...";
        Start-Sleep -s 3;
    };
    Write-Debug "Update-ACMEIdentifier";
    Update-ACMEIdentifier $FQDN | select Identifier, status, Expires;
};

if (-Not $MyACMEVault) {
    Write-Debug "Initialize-ACMEVault";
    Initialize-ACMEVault;
    Write-Debug "New-ACMERegistration";
    New-ACMERegistration -Contacts mailto:$MyMailAddress -AcceptTos;
};

if (-Not (Test-Path $CertPath)) {
    New-Item -Path $CertPath -ItemType Directory;
};

if (-Not (Test-Path $AuthPath)) {
    New-Item -Path $AuthPath -ItemType Directory;
    Write-Debug "Disable HTTPS on 'Default Web Site/.well-known'";
    c:\windows\system32\inetsrv\appcmd.exe set config "Default Web Site/.well-known" -section:system.webServer/security/access /sslFlags:"None" /commit:apphost;
};

#uncoment the lines bellow, after testing is done, to really request a certificate.
# Write-Debug "Register-FQDN $CN";
# Register-FQDN $CN;
# Write-Debug "Register-FQDN $SAN1";
# Register-FQDN $SAN1;
# Write-Debug "Register-FQDN $SAN2";
# Register-FQDN $SAN2;
# Write-Debug "Register-FQDN $SAN3";
# Register-FQDN $SAN3;
# Write-Debug "Register-FQDN $SAN4";
# Register-FQDN $SAN4;
# Write-Debug "New-ACMECertificate";
# New-ACMECertificate $CN -Generate -AlternativeIdentifierRefs $SAN1,$SAN2,$SAN3,$SAN4 -Alias $CertAlias;

# Prepear IIS For Register-FQDN
$isOverrideDenied = (Get-WebConfiguration //System.webserver/handlers -PSPath IIS:\ -Recurse -Metadata -Location "Default Web Site").OverrideMode -eq 'Deny'
if ($isOverrideDenied) {
    Set-WebConfiguration //System.webserver/handlers -Metadata overrideMode -Value Allow -PSPath 'IIS:\' -Location 'Default Web Site';
};

if ($SANs.Length -gt 0) {
    $SANs | ForEach-Object {
        Write-Debug "Register-FQDN $_";
        Register-FQDN $_;
    };
    Register-FQDN $CN;
    New-ACMECertificate $CN -Generate -AlternativeIdentifierRefs $SANs -Alias $CertAlias;
} else {
    Register-FQDN $CN;
    New-ACMECertificate $CN -Generate -Alias $CertAlias;
};

# Undo Prepear IIS for Register-FQDN
if ($isOverrideDenied) {
    Set-WebConfiguration //System.webserver/handlers -Metadata overrideMode -Value Deny -PSPath 'IIS:\' -Location 'Default Web Site';
};

Write-Debug "Submit-ACMECertificate";
Submit-ACMECertificate $CertAlias;

while (-Not (Update-ACMECertificate $CertAlias | select IssuerSerialNumber)) {
    Write-Debug "Waiting for certificate...";
    Start-Sleep 3;
};

Write-Debug "Update-ACMECertificate";
Update-ACMECertificate $CertAlias | select IssuerSerialNumber;

Set-Location $CertPath;

Write-Debug "Get-ACMECertificate";
Get-ACMECertificate $CertAlias -ExportPkcs12 $PfxFilePath;
# Get-ACMECertificate $CertAlias -ExportKeyPEM $PemPrivateKeyFilePath
# Get-ACMECertificate $CertAlias -ExportCertificatePEM $PemCertificateFilePath -ExportCertificateDER $SANDerCertificateFilePath
# Get-ACMECertificate $CertAlias -ExportIssuerPEM $LetsEncryptCAPEMCertificateFilePath -ExportIssuerDer $LetsEncryptCADerCertificateFilePath

$exchver =  Get-Command exsetup | ForEach-Object {
    $_.fileversioninfo.ProductVersion.Split("{.}");
};
switch ($exchver[0]) { 
    8 {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.Admin;
        Write-Debug "Exchange Version 8";
        Write-Debug "Import-ExchangeCertificate";
        Import-ExchangeCertificate -FileName $PfxFilePath -FriendlyName $CertAlias | Enable-ExchangeCertificate -Services "SMTP, IMAP, POP, IIS" -force;
        Write-Debug "iisreset";
        iisreset;
    };
    14 {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.E2010;
        Write-Debug "Exchange Version 2010";
        Write-Debug "Import-ExchangeCertificate";
        Import-ExchangeCertificate -FileName $PfxFilePath -FriendlyName $CertAlias | Enable-ExchangeCertificate -Services "SMTP, IMAP, POP, IIS" -force;
        Write-Debug "iisreset";
        iisreset;
    };
    15 {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn;
        Write-Debug "Exchange Version $(switch($exchver[1]) { "00" {"2013"}; "01" {"2016"}; }; )";
        Write-Debug "Import-ExchangeCertificate";
        Import-ExchangeCertificate -FileName $PfxFilePath -FriendlyName $CertAlias | Enable-ExchangeCertificate -Services "SMTP, IMAP, POP, IIS" -force;
        Write-Debug "iisreset";
        iisreset;
    };
    default {
        Write-Debug "No Exchange Server Management SnapIn found";
        Write-Debug "Skip Exchange processing;";
        # Implement IIS only handling here
        Set-Location IIS:\SslBindings;
        $CertThumb = (Import-PfxCertificate -FilePath $PfxFilePath -CertStoreLocation Cert:\LocalMachine\My -Exportable).Thumbprint;
        get-item cert:\LocalMachine\MY\$CertThumb | set-item -Path $((Get-ChildItem -Path . | Select-Object IPAddress,Port | ConvertTo-Csv -Delimiter "!" -NoTypeInformation | Select-Object -Skip 1) -replace "`"");
        iisreset;
        
        $isRGW = (Get-WindowsFeature -Name Remote-Desktop-Services).Installed;
        if($isRGW) {
            Import-Module RemoteDesktopServices;
            Set-Item -Path "RDS:\GatewayServer\SSLCertificate\Thumbprint" $CertThumb;
        };
    };
};

Write-Debug "Cleaning up...";
Remove-Item $AuthPath -Force -Recurse;
Remove-Item $PfxFilePath -Force;
Remove-Item "$env:ALLUSERSPROFILE\ACMESharp\sysVault" -Force -Recurse -Exclude "00-VAULT",".acme.vault";
Remove-Item "$env:LOCALAPPDATA\ACMESharp\userVault" -Force -Recurse -Exclude "00-VAULT",".acme.vault";

Set-Location $invokeLocation;

Stop-Transcript;
