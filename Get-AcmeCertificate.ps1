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
#$RemoteDesktopConnectionBrokerComputerName = "RDCB"
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
    Install-Module -Name ACMESharp -Scope AllUsers;
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Untrusted;
    Import-Module ACMESharp -ErrorAction Stop;
};
try {
    Import-Module ACMESharp.Providers.IIS -ErrorAction Stop;
} catch [System.IO.FileNotFoundException] {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force;
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted;
    Install-Module -Name ACMESharp.Providers.IIS -Scope AllUsers;
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Untrusted;
    Import-Module ACMESharp.Providers.IIS -ErrorAction Stop;
    Enable-ACMEExtensionModule -ModuleName ACMESharp.Providers.IIS;
    Remove-Module ACMESharp.Providers.IIS -ErrorAction Stop;
    Remove-Module ACMESharp -ErrorAction Stop;
    Import-Module ACMESharp -ErrorAction Stop;
    Import-Module ACMESharp.Providers.IIS -ErrorAction Stop;
};
Import-Module WebAdministration;
$MyACMEVault = Get-ACMEVault;

function Register-FQDN {
    param(
        [String]$FQDN,
        [String]$Alias
    );
    Write-Debug "New-ACMEIdentifier";
    New-ACMEIdentifier -Dns $FQDN -Alias $Alias | select status, Expires;
    Write-Debug "Complete-ACMEChallenge";
    $request = Complete-ACMEChallenge $Alias -ChallengeType http-01 -Handler iis -HandlerParameters @{ WebSiteRef = 'Default Web Site' } -Force
    $request | select Identifier, status, Expires | Write-Host;
    if ($request.Status -ne "valid") {
      Write-Debug "Submit-ACMEChallenge";
      # Break here, to check if the challenge can be reached publicly, the following command tells LE to validate it.
      Submit-ACMEChallenge $Alias -ChallengeType http-01 | select Identifier, status, Expires;
    }

    $Auth = 'placeholder'
    while ($Auth -ne "valid") {
        $Auth = ((Update-ACMEIdentifier $Alias -ChallengeType http-01).Challenges | Where-Object {$_.Type -eq "http-01"}).status;
        if($Auth -eq "invalid") {
            Write-Error "ACME Verifidation failed" -Category AuthenticationError;
            break;
        };
        Write-Debug "Waiting for verifidation...";
        Start-Sleep -s 3;
    };
    Write-Debug "Update-ACMEIdentifier";
    Update-ACMEIdentifier $Alias | select Identifier, status, Expires;
};

function Update-RemoteDesktopServicesCertificate {
    param(
      [string]$RDCBComputerName,
      [Parameter(Mandatory)][string]$CertThumb
    );
    if (-not [bool](Import-Module RemoteDesktop -ErrorAction SilentlyContinue)) {
        return;
    };
    $tmpPfxPath = Join-Path -Path $env:TEMP -ChildPath tmp.pfx;
    $tmpPw = ConvertTo-SecureString -String "TempPW_Ahjie7woosohghaepeim" -Force -AsPlainText;
    Export-PfxCertificate -cert "Cert:\LocalMachine\My\$CertThumb" -FilePath $tmpPfxPath -Force -NoProperties -Password $tmpPw;
    
    $collection = @{}; Get-RDServer -ConnectionBroker:$RDCBComputerName | ForEach-Object { $collection.Add($_.Server,$_.Roles) };
    $currentHostName = [Microsoft.RemoteDesktopServices.Common.CommonUtility]::GetLocalhostFullyQualifiedDomainname();
    
    $rdsh = [Microsoft.RemoteDesktopServices.Common.RDMSConstants]::RoleServiceRemoteDesktopSessionHost;
    $rdvh = [Microsoft.RemoteDesktopServices.Common.RDMSConstants]::RoleServiceRemoteDesktopVirtualizationHost;
    $rdcb = [Microsoft.RemoteDesktopServices.Common.RDMSConstants]::RoleServiceRemoteDesktopConnectionBroker;
    $rdwa = [Microsoft.RemoteDesktopServices.Common.RDMSConstants]::RoleServiceRemoteDesktopWebAccess;
    $rdgw = [Microsoft.RemoteDesktopServices.Common.RDMSConstants]::RoleServiceRemoteDesktopGateway;
    $rdls = [Microsoft.RemoteDesktopServices.Common.RDMSConstants]::RoleServiceRemoteDesktopLicensing;
    
    foreach($role in $collection[$currentHostName]) {
        switch($role) {
            $rdcb {
                Set-RDCertificate -Role RDPublishing -ImportPath $tmpPfxPath -Password $tmpPw -ConnectionBroker:$RDCBComputerName -Force;
                Set-RDCertificate -Role RDRedirector -ImportPath $tmpPfxPath -Password $tmpPw -ConnectionBroker:$RDCBComputerName -Force;
                (Get-CimInstance -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SSLCertificateSHA1Hash = $CertThumb;
            };
            $rdwa {
                Set-RDCertificate -Role RDWebAccess -ImportPath $tmpPfxPath -Password $tmpPw -ConnectionBroker:$RDCBComputerName -Force;
            };
            $rdgw {
                Set-RDCertificate -Role RDGateway -ImportPath $tmpPfxPath -Password $tmpPw -ConnectionBroker:$RDCBComputerName -Force;
            };
            $rdls {};
            $rdsh {};
            $rdvh {};
        };
    };
    Remove-Item -Path $tmpPfxPath;
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

# Prepear IIS For Register-FQDN
$isOverrideDenied = (Get-WebConfiguration //System.webserver/handlers -PSPath IIS:\ -Metadata -Location "Default Web Site").OverrideMode.ToString()
if ($isOverrideDenied -ne 'Allow') {
    Set-WebConfiguration //System.webserver/handlers -Metadata overrideMode -Value Allow -PSPath 'IIS:\' -Location 'Default Web Site';
};

$RequestAlias = '{0}_{1}' -f $CN, ([guid]::NewGuid()).Guid
$SANRequestAliases = @()
if ($SANs.Length -gt 0) {
    $SANs | ForEach-Object {
        $SANRequestAlias = '{0}_{1}' -f $_, $RequestAlias
        $SANRequestAliases += $SANRequestAlias
        Write-Debug "Register-FQDN $_";
        Register-FQDN -FQDN $_ -Alias $SANRequestAlias;
    };
    Register-FQDN -FQDN $CN -Alias $RequestAlias;
    New-ACMECertificate $RequestAlias -Generate -AlternativeIdentifierRefs $SANRequestAliases -Alias $CertAlias;
} else {
    Register-FQDN -FQDN $CN -Alias $RequestAlias;
    New-ACMECertificate $RequestAlias -Generate -Alias $CertAlias;
};

# Undo Prepear IIS for Register-FQDN
if ($isOverrideDenied -ne 'Allow') {
    Set-WebConfiguration //System.webserver/handlers -Metadata overrideMode -Value $isOverrideDenied -PSPath 'IIS:\' -Location 'Default Web Site';
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


# Import Certificate here, as even for exchange it is required to do this import up front, or it cannot be assigned for IIS
# so we need to do this in all cases anyway. It is also a good way to retrieve the Thumbprint.
$CertThumb = (Import-PfxCertificate -FilePath $PfxFilePath -CertStoreLocation Cert:\LocalMachine\My -Exportable).Thumbprint;

try {
    $exchver =  Get-Command exsetup -ErrorAction Stop | ForEach-Object {
        $_.fileversioninfo.ProductVersion.Split("{.}");
    };
} catch {
    $exchver = @($null);
};

# Import Certificate for Exchange and IIS (Importing a certificate to iis is different if exchange is installed)
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
        get-item cert:\LocalMachine\MY\$CertThumb | set-item -Path $((Get-ChildItem -Path . | Select-Object IPAddress,Port | ConvertTo-Csv -Delimiter "!" -NoTypeInformation | Select-Object -Skip 1) -replace "`"");
        iisreset;
    };
};

# Import certificate for Remote Desktop
Update-RemoteDesktopServicesCertificate -RDCBComputerName:$RemoteDesktopConnectionBrokerComputerName -CertThumb $CertThumb;



Write-Debug "Cleaning up...";
Remove-Item $AuthPath -Force -Recurse -ErrorAction SilentlyContinue;
Remove-Item $PfxFilePath -Force -ErrorAction SilentlyContinue;

Set-Location $invokeLocation;

Stop-Transcript;
