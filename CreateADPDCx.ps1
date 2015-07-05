configuration CreateADPDC 
{ 
   param 
   ( 
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Admincreds,

        [Int]$RetryCount=20,
        [Int]$RetryIntervalSec=30
    ) 
    
    Import-DscResource -ModuleName xActiveDirectory,xDisk, xNetworking, cDisk, xAdcsDeployment, xSystemSecurity, xWindowsUpdate

    [System.Management.Automation.PSCredential ]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)

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
			IsEnabled = $False
			UserRole  = "Administrators"
		}

		xIEEsc EnableIEEscUser
		{
			IsEnabled = $False
			UserRole  = "Users"
		}

        WindowsFeature DNS 
        { 
            Ensure = "Present" 
            Name = "DNS"
        }
        xDnsServerAddress DnsServerAddress 
        { 
            Address        = '127.0.0.1' 
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
        }
        xWaitforDisk Disk2
        {
             DiskNumber = 2
             RetryIntervalSec =$RetryIntervalSec
             RetryCount = $RetryCount
        }
        cDiskNoRestart ADDataDisk
        {
            DiskNumber = 2
            DriveLetter = "F"
        }
        WindowsFeature ADDSInstall 
        { 
            Ensure = "Present" 
            Name = "AD-Domain-Services"
        }  
        xADDomain FirstDS 
        {
            DomainName = $DomainName
            DomainAdministratorCredential = $DomainCreds
            SafemodeAdministratorPassword = $DomainCreds
            DatabasePath = "F:\NTDS"
            LogPath = "F:\NTDS"
            SysvolPath = "F:\SYSVOL"
        }
	WindowsFeature AD-Certificate
        {
            Ensure = 'Present'
            Name = 'AD-Certificate'
            DependsOn = '[xADDomain]FirstDS'
        }
        WindowsFeature ADCS-Web-Enrollment
        {
            Ensure = 'Present'
            Name = 'ADCS-Web-Enrollment'
            DependsOn = '[WindowsFeature]AD-Certificate'
        }
        xADCSCertificationAuthority ADCS
        {
            Ensure = 'Present'
            Credential = $DomainCreds
            CAType = 'EnterpriseRootCA'
            DependsOn = '[WindowsFeature]ADCS-Web-Enrollment'              
        }
        xADCSWebEnrollment CertSrv
        {
            Ensure = 'Present'
            Credential = $DomainCreds
            Name = 'CertSrv'
            DependsOn = '[WindowsFeature]ADCS-Web-Enrollment','[xADCSCertificationAuthority]ADCS'
        }  

        LocalConfigurationManager 
        {
             ActionAfterReboot = 'StopConfiguration'
        }
   }
} 