Configuration ContosoWebsite
{
  param ($MachineName)

  Node ($MachineName)
  {
     WindowsFeature WebServerManagementConsole
    {
        Name = "Web-Mgmt-Console"
        Ensure = "Present"
    }



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

   #script block to download apps and install them
    Script DownloadSilverlight
    {
        GetScript = {
            @{
                Result = "SilverlightInstall"
            }
        }
        TestScript = {
            Test-Path "C:\WindowsAzure\wpilauncher.exe"
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
            Test-Path "C:\WindowsAzure\en_skype_for_business_server_2015_x64_dvd_6622058.iso"
        }
        SetScript ={
            $source = "http://sfbfiles.blob.core.windows.net/software/en_skype_for_business_server_2015_x64_dvd_6622058.iso"
            $destination = "C:\WindowsAzure\en_skype_for_business_server_2015_x64_dvd_6622058.iso"
            Invoke-WebRequest $source -OutFile $destination
        }
    }

    Script ExtractSkyepForBusinessISO
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
            $destination = "C:\WindowsAzure\en_skype_for_business_server_2015_x64_dvd_6622058.iso"
			$folder = "c:\WindowsAzure\sfbserver\"
			$mount_params = @{ImagePath = $destination; PassThru = $true; ErrorAction = "Ignore"}
			$mount = Mount-DiskImage @mount_params

			 if($mount) {
				 $volume = Get-DiskImage -ImagePath $mount.ImagePath | Get-Volume
				 $source = $volume.DriveLetter + ":\*"
        
				 Write-Host "Extracting '$destination' to '$folder'..."
				 xcopy $source $folder /s /e /c
				 $hide = Dismount-DiskImage @mount_params
				 Write-Host "Copy complete"
			}
			else {
				 Write-Host "ERROR: Could not mount " $destination " check if file is already in use"
			}
		}
	}

    Package SkypeForBusiness_Core_Installation
        {
            Ensure = "Present"
            Name = "Microsoft Skype for Business Server"
            Path = "C:\WindowsAzure\sfbserver\Setup\amd64\setup.exe"
            ProductId = 'C3FF05AC-3EF0-45A8-A7F2-9FD3C0F6DE39'
            Arguments = '/BootstrapCore'
        }

    Script PrepareADforSFB {
		GetScript = {
            @{
                Result = ""
            }
        }
 
        SetScript = {
            $secpasswd = ConvertTo-SecureString "AzP@ssword1" -AsPlainText -Force
            $mycreds = New-Object System.Management.Automation.PSCredential ("AzAdmin", $secpasswd)
            $output = Invoke-Command -ScriptBlock { $(whoami) } -ComputerName localhost -Credential $mycreds -Verbose
            Write-Verbose $output
        }
 
        TestScript = {
            $false
        }

  }
} 