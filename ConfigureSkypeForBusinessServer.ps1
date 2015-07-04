#
# Copyright="© Microsoft Corporation. All rights reserved."
#

configuration ConfigureSkypeForBusinessServer
{
	
    param
    (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Admincreds,

        [parameter(Mandatory)]
        [String]$DatabaseServer,
      
        [Int]$RetryCount=30,
        [Int]$RetryIntervalSec=60

			#region Variables


    )
		Enable-CredSSPNTLM -DomainName $DomainName

        Write-Verbose "AzureExtensionHandler loaded continuing with configuration"

        [System.Management.Automation.PSCredential ]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)


        # Install Skype For Business Module
        $ModuleFilePath="$PSScriptRoot\SkypeForBusiness.psm1"
        $ModuleName = "SharepointServer"
        $PSModulePath = $Env:PSModulePath -split ";" | Select -Index 1
        $ModuleFolder = "$PSModulePath\$ModuleName"
        if (-not (Test-Path  $ModuleFolder -PathType Container)) {
            # mkdir $ModuleFolder
        }
        # Copy-Item $ModuleFilePath $ModuleFolder -Force

        Import-DscResource -ModuleName xComputerManagement, xActiveDirectory, xDisk, xCredSSP, cDisk, xNetworking, xSystemSecurity
		#Import-DSCResource -Module xSystemSecurity -Name xIEEsc


        Node localhost
        {
            Script ConfigureCPU
			{
				GetScript = {
					@{
						Result = ""
					}
				}
				TestScript = {
					$false
				}
				SetScript ={

				  # Set PowerPlan to "High Performance"
					$guid = (Get-WmiObject -Class Win32_PowerPlan -Namespace root\cimv2\power -Filter "ElementName='High Performance'").InstanceID.ToString()
					$regex = [regex]"{(.*?)}$"
					$plan = $regex.Match($guid).groups[1].value
					powercfg -S $plan
				}
			}
			xIEEsc EnableIEEscAdmin
			{
				IsEnabled = $True
				UserRole  = "Administrators"
			}

			xIEEsc EnableIEEscUser
			{
				IsEnabled = $False
				UserRole  = "Users"
			}


            xWaitforDisk Disk2
            {
                DiskNumber = 2
                RetryIntervalSec =$RetryIntervalSec
                RetryCount = $RetryCount
            }
            cDiskNoRestart SPDataDisk
            {
                DiskNumber = 2
                DriveLetter = "F"
                DependsOn = "[xWaitforDisk]Disk2"
            }
            xCredSSP Server 
            { 
                Ensure = "Present" 
                Role = "Server" 
            } 
            xCredSSP Client 
            { 
                Ensure = "Present" 
                Role = "Client" 
                DelegateComputers = "*.$Domain", "localhost"
            }
            WindowsFeature ADPS
            {
                Name = "RSAT-AD-PowerShell"
                Ensure = "Present"
                DependsOn = "[cDiskNoRestart]SPDataDisk"
            }
            WindowsFeature NET-Framework-Core
            {
                Name = "NET-Framework-Core"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]ADPS"
            }
            WindowsFeature RSAT-ADDS
            {
                Name = "RSAT-ADDS"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]NET-Framework-Core"
            }
            WindowsFeature RSAT-DNS-SERVER
            {
                Name = "RSAT-DNS-SERVER"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]RSAT-ADDS"
            }
            WindowsFeature Windows-Identity-Foundation
            {
                Name = "Windows-Identity-Foundation"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]RSAT-DNS-SERVER"
            }
            WindowsFeature Web-Static-Content
            {
                Name = "Web-Static-Content"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]Windows-Identity-Foundation"
            }
            WindowsFeature Web-Default-Doc
            {
                Name = "Web-Default-Doc"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]Web-Static-Content"
            }
            WindowsFeature Web-Http-Errors
            {
                Name = "Web-Http-Errors"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]Web-Default-Doc"
            }
            WindowsFeature Web-Asp-Net
            {
                Name = "Web-Asp-Net"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]Web-Http-Errors"
            }
            WindowsFeature Web-Net-Ext
            {
                Name = "Web-Net-Ext"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]Web-Asp-Net"
            }
            WindowsFeature Web-ISAPI-Ext
            {
                Name = "Web-ISAPI-Ext"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]Web-Net-Ext"
            }
            WindowsFeature Web-ISAPI-Filter
            {
                Name = "Web-ISAPI-Filter"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]Web-ISAPI-Ext"
            }
            WindowsFeature Web-Http-Logging
            {
                Name = "Web-Http-Logging"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]Web-ISAPI-Filter"
            }
            WindowsFeature Web-Log-Libraries
            {
                Name = "Web-Log-Libraries"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]Web-Http-Logging"
            }
            WindowsFeature Web-Request-Monitor
            {
                Name = "Web-Request-Monitor"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]Web-Log-Libraries"
            }
            WindowsFeature Web-Http-Tracing
            {
                Name = "Web-Http-Tracing"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]Web-Request-Monitor"
            }
            WindowsFeature Web-Basic-Auth
            {
                Name = "Web-Basic-Auth"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]Web-Http-Tracing"
            }
            WindowsFeature Web-Windows-Auth
            {
                Name = "Web-Windows-Auth"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]Web-Basic-Auth"
            }
            WindowsFeature Web-Client-Auth
            {
                Name = "Web-Client-Auth"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]Web-Windows-Auth"
            }
            WindowsFeature Web-Filtering
            {
                Name = "Web-Filtering"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]Web-Client-Auth"
            }
            WindowsFeature Web-Stat-Compression
            {
                Name = "Web-Stat-Compression"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]Web-Filtering"
            }
            WindowsFeature Web-Dyn-Compression
            {
                Name = "Web-Dyn-Compression"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]Web-Stat-Compression"
            }
            WindowsFeature NET-WCF-HTTP-Activation45
            {
                Name = "NET-WCF-HTTP-Activation45"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]Web-Dyn-Compression"
            }
            WindowsFeature Web-Asp-Net45
            {
                Name = "Web-Asp-Net45"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]NET-WCF-HTTP-Activation45"
            }
            WindowsFeature Web-Mgmt-Tools
            {
                Name = "Web-Mgmt-Tools"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]Web-Asp-Net45"
            }
            WindowsFeature Web-Scripting-Tools
            {
                Name = "Web-Scripting-Tools"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]Web-Mgmt-Tools"
            }
            WindowsFeature Server-Media-Foundation
            {
                Name = "Server-Media-Foundation"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]Web-Scripting-Tools"
            }
            xWaitForADDomain DscForestWait 
            { 
                DomainName = $DomainName 
                DomainUserCredential= $DomainCreds
                RetryCount = $RetryCount 
                RetryIntervalSec = $RetryIntervalSec 
                DependsOn = "[WindowsFeature]Server-Media-Foundation"      
            }
            xComputer DomainJoin
            {
                Name = $env:COMPUTERNAME
                DomainName = $DomainName
                Credential = $DomainCreds
                DependsOn = "[xWaitForADDomain]DscForestWait" 
            }


#New
   #script block to download apps and install them
    Script DownloadSilverlight
    {
        GetScript = {
            @{
                Result = "SilverlightInstall"
            }
        }
        TestScript = {
            Test-Path "C:\WindowsAzure\Silverlight_x64.exe"
        }
        SetScript ={
            $source = "http://download.microsoft.com/download/F/8/C/F8C0EACB-92D0-4722-9B18-965DD2A681E9/30514.00/Silverlight_x64.exe"
            $destination = "C:\WindowsAzure\Silverlight_x64.exe"
            Invoke-WebRequest $source -OutFile $destination
        }
    }

    Package Silverlight_Installation
        {
            Ensure = "Present"
            Name = "Microsoft Silverlight 5"
            Path = "C:\WindowsAzure\Silverlight_x64.exe"
            ProductId = '89F4137D-6C26-4A84-BDB8-2E5A4BB71E00'
            Arguments = '/q'
        }

	Script DownloadAndExtractHotFixKB2982006
    {
        GetScript = {
            @{
                Result = "HotFix KB2982006"
            }
        }
        TestScript = {
            Test-Path "C:\WindowsAzure\478232_intl_x64_zip.exe"
        }
        SetScript ={
            $source = "http://hotfixv4.microsoft.com/Windows 8.1/Windows Server 2012 R2/sp1/Fix514814/9600/free/478232_intl_x64_zip.exe"
            $destination = "C:\WindowsAzure\478232_intl_x64_zip.exe"
            Invoke-WebRequest $source -OutFile $destination

			Add-Type -assembly "system.io.compression.filesystem"
			[io.compression.zipfile]::ExtractToDirectory($destination, "C:\WindowsAzure\")
        }
    }

    Package InstallHotFixKB2982006
        {
            Ensure = "Present"
            Name = "Hotfix KB2982006"
            Path = "c:\windows\system32\wusa.exe"
            ProductId = ''
            Arguments = 'C:\WindowsAzure\Windows8.1-KB2982006-x64.msu /quiet /norestart'
        }


    Script DownloadSkypeForBusinessISO
    {
        GetScript = {
            @{
                Result = "DownloadSkypeForBusinessISO"
            }
        }
        TestScript = {
            Test-Path "C:\WindowsAzure\SfB-E-9319.0-enUS.ISO"
        }
        SetScript ={
            $source = "http://care.dlservice.microsoft.com/dl/download/6/6/5/665C9DD5-9E1E-4494-8709-4A3FFC35C6A0/SfB-E-9319.0-enUS.ISO"
            $destination = "C:\WindowsAzure\SfB-E-9319.0-enUS.ISO"
            Invoke-WebRequest $source -OutFile $destination
			# Mount ISO
            $destination = "C:\WindowsAzure\SfB-E-9319.0-enUS.ISO"
			$mount =  Mount-DiskImage -ImagePath $destination
        }
    }


    Package SkypeForBusiness_Core_Installation
        {
            Ensure = "Present"
            Name = "Microsoft Skype for Business Server"
            #Path = (Get-DiskImage -ImagePath "C:\WindowsAzure\SfB-E-9319.0-enUS.ISO" | Get-Volume).DriveLetter + ":\Setup\amd64\setup.exe"
            Path = "G:\Setup\amd64\setup.exe"
			ProductId = 'C3FF05AC-3EF0-45A8-A7F2-9FD3C0F6DE39'
            Arguments = '/BootstrapCore'
        }

		Script SFBPrepareSchema
		{
			GetScript = {
				@{
					Result = ""
				}
			}
			TestScript = {
				$false
			}
            SetScript = ([String]{            
                $password = ConvertTo-SecureString 'AzP@ssword1' -AsPlainText -Force
                $credential = New-Object System.Management.Automation.PSCredential "ucpilot\AzAdmin",$password
                Invoke-Command {
			        whoami > c:\w.txt 
			        Import-Module "C:\Program Files\Common Files\Skype for Business Server 2015\Modules\SkypeForBusiness\SkypeForBusiness.psd1"
                    Import-Module ActiveDirectory
			        $Domain = Get-ADDomain
                    $Computer = $env:computername + '.'+$Domain.DNSRoot
                    #$SQLServer = "SQLServer" + '.'+$Domain.DNSRoot
                    $DC = Get-ADDomainController
                    $Sbase = "CN=Configuration,"+$Domain.DistinguishedName

                    Install-CSAdServerSchema -Confirm:$false -Verbose -Report "C:\WindowsAzure\Logs\Install-CSAdServerSchema.html"
                    Enable-CSAdForest  -Verbose -Confirm:$false -Report "C:\WindowsAzure\Logs\Enable-CSAdForest.html"
                    Enable-CSAdDomain -Verbose -Confirm:$false -Report "C:\WindowsAzure\Logs\Enable-CSAdDomain.html"
                    Add-ADGroupMember -Identity CSAdministrator -Members "Domain Admins"
                    Add-ADGroupMember -Identity RTCUniversalServerAdmins -Members "Domain Admins"
					Install-CsDatabase -CentralManagementDatabase -SqlServerFqdn $using:DatabaseServer 
					# -SqlInstanceName rtc
					Set-CsConfigurationStoreLocation -SqlServerFqdn $using:DatabaseServer 
					# Set-CsConfigurationStoreLocation -SqlServerFqdn $Computer -SqlInstanceName rtc

				} -ComputerName sfbserver1.ucpilot.com -EnableNetworkAccess -Credential $credential -Authentication CredSSP
            })
			
		}


#            LocalConfigurationManager 
#            {
#              ActionAfterReboot = 'StopConfiguration'
#            }
        }  
}

function Enable-CredSSPNTLM
{ 
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainName
    )
    
    # This is needed for the case where NTLM authentication is used

    Write-Verbose 'STARTED:Setting up CredSSP for NTLM'
   
    Enable-WSManCredSSP -Role client -DelegateComputer localhost, *.$DomainName -Force -ErrorAction SilentlyContinue
    Enable-WSManCredSSP -Role server -Force -ErrorAction SilentlyContinue

    if(-not (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -ErrorAction SilentlyContinue))
    {
        New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name '\CredentialsDelegation' -ErrorAction SilentlyContinue
    }

    if( -not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name 'AllowFreshCredentialsWhenNTLMOnly' -ErrorAction SilentlyContinue))
    {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name 'AllowFreshCredentialsWhenNTLMOnly' -value '1' -PropertyType dword -ErrorAction SilentlyContinue
    }

    if (-not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name 'ConcatenateDefaults_AllowFreshNTLMOnly' -ErrorAction SilentlyContinue))
    {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name 'ConcatenateDefaults_AllowFreshNTLMOnly' -value '1' -PropertyType dword -ErrorAction SilentlyContinue
    }

    if(-not (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -ErrorAction SilentlyContinue))
    {
        New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name 'AllowFreshCredentialsWhenNTLMOnly' -ErrorAction SilentlyContinue
    }

    if (-not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name '1' -ErrorAction SilentlyContinue))
    {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name '1' -value "wsman/$env:COMPUTERNAME" -PropertyType string -ErrorAction SilentlyContinue
    }

    if (-not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name '2' -ErrorAction SilentlyContinue))
    {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name '2' -value "wsman/localhost" -PropertyType string -ErrorAction SilentlyContinue
    }

    if (-not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name '3' -ErrorAction SilentlyContinue))
    {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name '3' -value "wsman/*.$DomainName" -PropertyType string -ErrorAction SilentlyContinue
    }

    Write-Verbose "DONE:Setting up CredSSP for NTLM"
}

