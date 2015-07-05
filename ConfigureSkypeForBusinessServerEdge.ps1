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

        Import-DscResource -ModuleName xComputerManagement, xActiveDirectory, xDisk, xCredSSP, cDisk, xNetworking, xSystemSecurity, xWindowsUpdate

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
#Registry RegistryExample
#{
#    Ensure = "Present"  # You can also set Ensure to "Absent"
#    Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Security"
#    ValueName = "DisableSecuritySettingsCheck"
#    ValueType = "Dword"
#    ValueData = 1
#}

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
            WindowsFeature NET-Framework-45-Core
            {
                Name = "NET-Framework-45-Core"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]ADPS"
            }
            WindowsFeature Windows-Identity-Foundation
            {
                Name = "Windows-Identity-Foundation"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]NET-Framework-45-Core"
            }
            WindowsFeature Telnet-Client
            {
                Name = "Telnet-Client"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]Windows-Identity-Foundation"
            }



    Script DownloadSkypeForBusinessISO
    {
        GetScript = {
            @{
                Result = "DownloadSkypeForBusinessISO"
            }
        }
        TestScript = {
            $false
        }
        SetScript ={
            $source = "http://care.dlservice.microsoft.com/dl/download/6/6/5/665C9DD5-9E1E-4494-8709-4A3FFC35C6A0/SfB-E-9319.0-enUS.ISO"
            $destination = "C:\WindowsAzure\SfB-E-9319.0-enUS.ISO"
            
				Invoke-WebRequest $source -OutFile $destination
				# Mount ISO
				$destination = "C:\WindowsAzure\SfB-E-9319.0-enUS.ISO"
				$mount =  Mount-DiskImage -ImagePath $destination
				$source = (Get-DiskImage -ImagePath "C:\WindowsAzure\SfB-E-9319.0-enUS.ISO" | Get-Volume).DriveLetter + ":\*"
				mkdir "C:\WindowsAzure\SfB"
				$folder = "c:\WindowsAzure\SfB\"
				cp $source $folder -Recurse -Force
			
        }
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


		xHotfix HotfixInstall 
		{ 
			Ensure = "Present" 
            Path = "C:\WindowsAzure\Windows8.1-KB2982006-x64.msu"
			Id = "KB2982006" 
			Log = "c:\WindowsAzure\logs\hotfix-KB2982006.etl"

		}  


    Package SkypeForBusiness_Core_Installation
        {
            Ensure = "Present"
            Name = "Microsoft Skype for Business Server"
            Path = "C:\WindowsAzure\SfB\Setup\amd64\setup.exe"
			ProductId = 'C3FF05AC-3EF0-45A8-A7F2-9FD3C0F6DE39'
            Arguments = '/BootstrapCore'
        }

    Script DownloadRootCert
    {
        GetScript = {
            @{
                Result = "DownloadRootCert"
            }
        }
        TestScript = {
            Test-Path "C:\WindowsAzure\certnew.cer"
        }
        SetScript ={
            $source = "http://adserver.ucpilot.com/certsrv/certnew.cer?ReqID=CACert&Renewal=0&Enc=bin"
            $destination = "C:\WindowsAzure\certnew.cer"
            Invoke-WebRequest $source -OutFile $destination

			#Import Certificate
			Import-Certificate -FilePath "C:\WindowsAzure\certnew.Cer" -CertStoreLocation 'Cert:\LocalMachine\Trusted Root Certification Authorities' -Verbose 

            $source = "https://sfbserver1.ucpilot.com/meet/config.zip"
            $destination = "C:\WindowsAzure\config.zip"
            Invoke-WebRequest $source -OutFile $destination


        }
    }




		Script SFBConfigure
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
	           #Path = (Get-DiskImage -ImagePath "C:\WindowsAzure\SfB-E-9319.0-enUS.ISO" | Get-Volume).DriveLetter + ":\Setup\amd64\setup.exe"
                $password = ConvertTo-SecureString 'AzP@ssword1' -AsPlainText -Force
                $credential = New-Object System.Management.Automation.PSCredential "ucpilot\AzAdmin",$password
                Invoke-Command {
			        whoami > c:\w.txt 
			        Import-Module "C:\Program Files\Common Files\Skype for Business Server 2015\Modules\SkypeForBusiness\SkypeForBusiness.psd1"

					# Set-CsConfigurationStoreLocation -SqlServerFqdn 'sqlserver.ucpilot.com' -Verbose -Report "C:\WindowsAzure\Logs\Set-CsConfigurationStoreLocation.html"
					# Set-CsConfigurationStoreLocation -SqlServerFqdn $Computer -SqlInstanceName rtc

				} -ComputerName localhost -EnableNetworkAccess -Credential $credential -Authentication CredSSP
            })
			
		}
			xIEEsc EnableIEEscAdmin
			{
				IsEnabled = $false
				UserRole  = "Administrators"
			}

			xIEEsc EnableIEEscUser
			{
				IsEnabled = $False
				UserRole  = "Users"
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

#ConfigureSkypeForBusinessServer -DomainName 'ucpilot.com' -DatabaseServer 'sqlserver.ucpilot.com' -OutputPath c:\DSC
#Start-DscConfiguration -Path C:\DSC -Verbose -Wait -Force
