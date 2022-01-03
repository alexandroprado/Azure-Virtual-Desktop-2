#Requires -RunAsAdministrator
#Requires -Version 7.0.8

if ($PSVersionTable.PSVersion -le [version]"7.0.7") {
    throw "This version of Powershell is greater that 7.0.8"
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#Check of NuGet is installed.
if (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue) {
    Write-Host "NuGet Already Installed"
} else {
    try {
        Install-PackageProvider -Name NuGet -Confirm:$False -Force  
    }
    catch [Exception] {
        $_.message 
        exit
    }
}

#Check of Az.Accounts is installed.
if (Get-Module -ListAvailable -Name Az.Accounts) {
    Write-Host "Az.Accounts Already Installed"
} else {
    try {
        Install-Module -Name Az.Accounts -Repository PSGallery -Confirm:$False -Force  
    }
    catch [Exception] {
        $_.message 
        exit
    }
}

#Check for update Az.Accounts
Get-Module -Name Az.Accounts -ListAvailable | ForEach-Object {
    $moduleName = $_.Name
    $currentVersion = [Version]$_.Version

    Write-Host "Current version $moduleName [$currentVersion]"

    # Get latest version from gallery
    $latestVersion = [Version](Find-Module -Name $moduleName).Version
    
    # Only proceed if latest version in gallery is greater than your current version
    if ($latestVersion -gt $currentVersion) {
        Write-Host "Found latest version $modulename [$latestVersion] from $($latestVersionModule.Repository)"

        # Check if latest version is already installed before updating
        $latestVersionModule = Get-InstalledModule -Name $moduleName -RequiredVersion $latestVersion -ErrorAction SilentlyContinue
        if ($null -eq $latestVersionModule) {
            Write-Host "Updating $moduleName Module from [$currentVersion] to [$latestVersion]"
            Update-Module -Name $moduleName -RequiredVersion $latestVersion -Force
        }
        else {
            Write-Host "No update needed, $modulename [$latestVersion] already exists"
        }

        # Uninstall outdated version
        Write-Host "Uninstalling $moduleName [$currentVersion]"
        Uninstall-Module -Name $moduleName -RequiredVersion $currentVersion -Force
    }

    # Otherwise we already have most up to date version
    else {
        Write-Host "$moduleName already up to date"
    }
}

#Check of Az.DesktopVirtualization is installed.
if (Get-Module -ListAvailable -Name Az.DesktopVirtualization) {
    Write-Host "Az.DesktopVirtualization Already Installed"
} else {
    try {
        Install-Module -Name Az.DesktopVirtualization -Repository PSGallery -Confirm:$False -Force  
    }
    catch [Exception] {
        $_.message 
        exit
    }
}

#Check for update Az.DesktopVirtualization
Get-Module -Name Az.DesktopVirtualization -ListAvailable | ForEach-Object {
    $moduleName = $_.Name
    $currentVersion = [Version]$_.Version

    Write-Host "Current version $moduleName [$currentVersion]"

    # Get latest version from gallery
    $latestVersion = [Version](Find-Module -Name $moduleName).Version
    
    # Only proceed if latest version in gallery is greater than your current version
    if ($latestVersion -gt $currentVersion) {
        Write-Host "Found latest version $modulename [$latestVersion] from $($latestVersionModule.Repository)"

        # Check if latest version is already installed before updating
        $latestVersionModule = Get-InstalledModule -Name $moduleName -RequiredVersion $latestVersion -ErrorAction SilentlyContinue
        if ($null -eq $latestVersionModule) {
            Write-Host "Updating $moduleName Module from [$currentVersion] to [$latestVersion]"
            Update-Module -Name $moduleName -RequiredVersion $latestVersion -Repository PSGallery -Confirm:$False -Force
        }
        else {
            Write-Host "No update needed, $modulename [$latestVersion] already exists"
        }

        # Uninstall outdated version
        Write-Host "Uninstalling $moduleName [$currentVersion]"
        Uninstall-Module -Name $moduleName -RequiredVersion $currentVersion -Confirm:$False -Force
    }

    # Otherwise we already have most up to date version
    else {
        Write-Host "$moduleName already up to date"
    }
}

#Check of Az.Network is installed.
if (Get-Module -ListAvailable -Name Az.Network) {
    Write-Host "Az.Network Already Installed"
} else {
    try {
        Install-Module -Name Az.Network -Repository PSGallery -Confirm:$False -Force  
    }
    catch [Exception] {
        $_.message 
        exit
    }
}

#Check for update Az.Network
Get-Module -Name Az.Network -ListAvailable | ForEach-Object {
    $moduleName = $_.Name
    $currentVersion = [Version]$_.Version

    Write-Host "Current version $moduleName [$currentVersion]"

    # Get latest version from gallery
    $latestVersion = [Version](Find-Module -Name $moduleName).Version
    
    # Only proceed if latest version in gallery is greater than your current version
    if ($latestVersion -gt $currentVersion) {
        Write-Host "Found latest version $modulename [$latestVersion] from $($latestVersionModule.Repository)"

        # Check if latest version is already installed before updating
        $latestVersionModule = Get-InstalledModule -Name $moduleName -RequiredVersion $latestVersion -ErrorAction SilentlyContinue
        if ($null -eq $latestVersionModule) {
            Write-Host "Updating $moduleName Module from [$currentVersion] to [$latestVersion]"
            Update-Module -Name $moduleName -RequiredVersion $latestVersion -Force
        }
        else {
            Write-Host "No update needed, $modulename [$latestVersion] already exists"
        }

        # Uninstall outdated version
        Write-Host "Uninstalling $moduleName [$currentVersion]"
        Uninstall-Module -Name $moduleName -RequiredVersion $currentVersion -Force
    }

    # Otherwise we already have most up to date version
    else {
        Write-Host "$moduleName already up to date"
    }
}

#Check of Az.Compute is installed.
if (Get-Module -ListAvailable -Name Az.Compute) {
    Write-Host "Az.Compute Already Installed"
} else {
    try {
        Install-Module -Name Az.Compute -Repository PSGallery -Confirm:$False -Force  
    }
    catch [Exception] {
        $_.message 
        exit
    }
}

#Check for update Az.Compute
Get-Module -Name Az.Compute -ListAvailable | ForEach-Object {
    $moduleName = $_.Name
    $currentVersion = [Version]$_.Version

    Write-Host "Current version $moduleName [$currentVersion]"

    # Get latest version from gallery
    $latestVersion = [Version](Find-Module -Name $moduleName).Version
    
    # Only proceed if latest version in gallery is greater than your current version
    if ($latestVersion -gt $currentVersion) {
        Write-Host "Found latest version $modulename [$latestVersion] from $($latestVersionModule.Repository)"

        # Check if latest version is already installed before updating
        $latestVersionModule = Get-InstalledModule -Name $moduleName -RequiredVersion $latestVersion -ErrorAction SilentlyContinue
        if ($null -eq $latestVersionModule) {
            Write-Host "Updating $moduleName Module from [$currentVersion] to [$latestVersion]"
            Update-Module -Name $moduleName -RequiredVersion $latestVersion -Force
        }
        else {
            Write-Host "No update needed, $modulename [$latestVersion] already exists"
        }

        # Uninstall outdated version
        Write-Host "Uninstalling $moduleName [$currentVersion]"
        Uninstall-Module -Name $moduleName -RequiredVersion $currentVersion -Force
    }

    # Otherwise we already have most up to date version
    else {
        Write-Host "$moduleName already up to date"
    }
}

#Check of Az.Resources is installed.
if (Get-Module -ListAvailable -Name Az.Resources) {
    Write-Host "Az.Resources Already Installed"
} else {
    try {
        Install-Module -Name Az.Resources -Repository PSGallery -Confirm:$False -Force  
    }
    catch [Exception] {
        $_.message 
        exit
    }
}

#Check for update Az.Resources
Get-Module -Name Az.Resources -ListAvailable | ForEach-Object {
    $moduleName = $_.Name
    $currentVersion = [Version]$_.Version

    Write-Host "Current version $moduleName [$currentVersion]"

    # Get latest version from gallery
    $latestVersion = [Version](Find-Module -Name $moduleName).Version
    
    # Only proceed if latest version in gallery is greater than your current version
    if ($latestVersion -gt $currentVersion) {
        Write-Host "Found latest version $modulename [$latestVersion] from $($latestVersionModule.Repository)"

        # Check if latest version is already installed before updating
        $latestVersionModule = Get-InstalledModule -Name $moduleName -RequiredVersion $latestVersion -ErrorAction SilentlyContinue
        if ($null -eq $latestVersionModule) {
            Write-Host "Updating $moduleName Module from [$currentVersion] to [$latestVersion]"
            Update-Module -Name $moduleName -RequiredVersion $latestVersion -Force
        }
        else {
            Write-Host "No update needed, $modulename [$latestVersion] already exists"
        }

        # Uninstall outdated version
        Write-Host "Uninstalling $moduleName [$currentVersion]"
        Uninstall-Module -Name $moduleName -RequiredVersion $currentVersion -Force
    }

    # Otherwise we already have most up to date version
    else {
        Write-Host "$moduleName already up to date"
    }
}

Import-Module Az.Accounts
Import-Module Az.DesktopVirtualization
Import-Module Az.Network
Import-Module Az.Compute
Import-Module Az.Resources

# Disconnect all existing Azure connections
do
{
    Disconnect-AzAccount
    $azureContext = Get-AzContext
} until (!$azureContext)

Connect-AzAccount

#To suppress these warning messages
Set-Item Env:\SuppressAzurePowerShellBreakingChangeWarnings "true"

$ResourceGroupName = "NLUpdateRG"
$GetVM = Get-AzVM -ResourceGroupName $ResourceGroupName
$VMName = $GetVM.Name
$Location = $GetVM.Location
$SourceVirtualMachineId = $GetVM.id
Clear-Host
# Remote Sysprep
Write-Host "Sysprep $VMName"
$FileUri = "https://raw.githubusercontent.com/Ruthhl3ss/public/main/AzureVMExtensions/SysPrepScript.ps1"
Set-AzVMCustomScriptExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -Location $Location -FileUri $FileUri -Run 'SysPrepScript.ps1' -Name SysPrep
# Remove Sysprep AzVMExtension
Write-Host "Remove-AzVMExtension"
Get-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $VMName  | where {$_.ExtensionType -eq "CustomScriptExtension"} | Remove-AzVMExtension -Force
# Stop AzVM
Clear-Host
Write-Host "Stopping VM"
Stop-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -Force

function test-VMstatus($VMName) {
    $vmStatus = (Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -Status).Statuses
    return $PowerState = $vmStatus[1].DisplayStatus
}
Write-Host "Waiting for VM to be deallocated"
# After sysprep check if vm is deallocated
do {
    $status = test-vmStatus -VMName $VMName
    $status
Start-Sleep 10
} until ($status -eq "VM deallocated")

# When the VM is deallocated it is time to generalize the VM
Write-Host "Generalized $VMName"
Set-AzVm -ResourceGroupName $ResourceGroupName -Name $VMName -Generalized

# Create the image configuration.
$image = New-AzImageConfig -Location $location -SourceVirtualMachineId $SourceVirtualMachineId

# Create the image.
Write-Host "Create Managed Image $VMName for SIG"
$managedImage = New-AzImage -Image $image -ImageName $VMName -ResourceGroupName $ResourceGroupName

# Adding vm to SIG.
Write-Host "Adding $VMName $version to SIG"
$time = (get-date).ToString('T')
Write-Host "Start at $time"
$date = get-date -format "yyyy-MM-dd"
$version = $date.Replace("-", ".")
# Configuring paramaters
$imageVersionParameters = @{
    GalleryImageDefinitionName = "AVD-NL"
    GalleryImageVersionName    = $version
    GalleryName                = "SIG"
    ResourceGroupName          = "SIG"
    Location                   = $location
    Source                     = $managedImage.id.ToString()
}
# Doing the job
New-AzGalleryImageVersion @imageVersionParameters

Clear-Host
Write-Host "Remove $ResourceGroupName"
Remove-AzResourceGroup -Name $ResourceGroupName -Force
#######################################################################################################################

$hostpoolName = "AVD-NL"
# Get hostpool information
$hostpool = Get-AzWvdHostPool | ? { $_.Name -eq $hostpoolName }
# Get hostpool resourceGroup
$resourceGroup = ($hostpool).id.split("/")[4].ToUpper()
# Get hostpool Subscription
$hostpoolSubscription = ($hostpool).id.split("/")[2]
# Get current sessionhost information
$sessionHosts = Get-AzWvdSessionHost -ResourceGroupName $resourceGroup -HostPoolName $hostpool.name
# Get latest sessionhost information
$sessionHost = $sessionHosts[-1]
# Get current sessionhost configuration, for setting parameters
$existingHostName = $sessionHost.Id.Split("/")[-1]
# Get rdshPrefix for parameter
$prefix0 = $existingHostName.Split("-")[0]
$prefix1 = $existingHostName.Split("-")[1]
# Get parameters rdshPrefix
$rdshPrefix = $prefix0 + "-" + $prefix1
# Get parameter domain 
$domein1 = $existingHostName.Split(".")[-2]
$domein2 = $existingHostName.Split(".")[-1]
$domain = $domein1 + "." + $domein2
# Get current Virtule Machine information
$currentVmInfo = Get-AzVM -Name $existingHostName.Split(".")[0]
# Get parameter vmInitialNumber "VM name prefix initial number." + 1
$vmInitialNumber = [int]$existingHostName.Split("-")[-1].Split(".")[0] + 1
# Get current Network information
$vmNetworkInformation = (Get-AzNetworkInterface -ResourceId $currentVmInfo.NetworkProfile.NetworkInterfaces.id)
# Get parameter existingVnetName
$existingVnetName = $vmNetworkInformation.IpConfigurations.subnet.id.split("/")[-3]
# Get parameter virtualNetworkResourceGroupName
$virtualNetworkResourceGroupName = $vmNetworkInformation.IpConfigurations.subnet.id.split("/")[4]
# Get parameter existingSubnetName
$existingSubnetName = $vmNetworkInformation.IpConfigurations.subnet.id.split("/")[-1]
# Get current virtualNetwork
$virtualNetwork = Get-AzVirtualNetwork -Name $existingVnetName
# Get current subnetId for new Virtule Machine
$subnetId = $virtualNetwork.Subnets | Where-Object Name -eq $existingSubnetName | Select-Object -ExpandProperty Id
# Get the image gallery information for getting latest image
$imageReference = ($currentVmInfo.storageprofile.ImageReference).id
# Get the image gallery ResourceGroup
$galleryResourceGroupName = $imageReference.Split("/")[4]
# Get the image gallery name
$galleryName = $imageReference.Split("/")[8]
# Get the image gallery Definition
$GalleryImageDefinitionName = $imageReference.Split("/")[10]
# Get the image gallery Definition latest version
$latestImageVersion = (Get-AzGalleryImageVersion -ResourceGroupName $galleryResourceGroupName -GalleryName $galleryName -GalleryImageDefinitionName $GalleryImageDefinitionName)[-1]
# Get parameter domain 
$domein1 = $existingHostName.Split(".")[-2]
$domein2 = $existingHostName.Split(".")[-1]
$domain = $domein1 + "." + $domein2
#DomainAdmin
$GetAzKeyVault = Get-AzKeyVault
$DomainJoinUsername = Get-AzKeyVaultSecret -VaultName $GetAzKeyVault.VaultName -Name DomainJoinUsername -AsPlainText
$DomainJoinPassword = Get-AzKeyVaultSecret -VaultName $GetAzKeyVault.VaultName -Name DomainJoinPassword
#LocalAdmin
$vmAdministratorAccountUsername = "VMLocalAdminUser"
$vmAdministratorAccountPassword = Get-AzKeyVaultSecret -VaultName $GetAzKeyVault.VaultName -Name "LocalAdminPassword"

# Function AVD Hostpool registration key
function Get-avdHostpoolToken($hostpoolName,$resourceGroup,$hostpoolSubscription) {
    $now = get-date
    # Create a registration key for adding machines to the WVD Hostpool
    $registered = Get-AzWvdRegistrationInfo -SubscriptionId $hostpoolSubscription -ResourceGroupName $resourceGroup -HostPoolName $hostpoolName
    if (($null -eq $registered.ExpirationTime) -or ($registered.ExpirationTime -le ($now))) {
        $registered = New-AzWvdRegistrationInfo -SubscriptionId $hostpoolSubscription -ResourceGroupName $resourceGroup -HostPoolName $hostpool.Name -ExpirationTime $now.AddHours(4)
    }
    if ($registered.Token) {
    }
    return $registered
}
# Get AVD Hostpool registration key
$hostPoolRegistration = Get-AvdHostpoolToken -hostpoolName $hostpoolName -resourceGroup $resourceGroup -hostpoolSubscription $hostpoolSubscription
if ($hostPoolRegistration) {
    $hostPoolToken = (ConvertTo-SecureString -AsPlainText -Force ($hostPoolRegistration).Token)
}

$tags = @{
    ImageVersion = $latestImageVersion.Name
    HostPool     = $hostpoolName
}

$templateParameters = @{
    availabilityOption              = "None"
    availabilityZone                = "1"
    vmImageType                     = "CustomImage"
    vmNamePrefix                    = $rdshPrefix 
    virtualNetworkResourceGroupName = $virtualNetworkResourceGroupName
    existingVnetName                = $existingVnetName
    existingSubnetName              = $existingSubnetName
    resourceGroupName               = $resourceGroup
    hostpoolName                    = $hostpoolName
    domain                          = $domain
    administratorAccountUsername    = $DomainJoinUsername
    administratorAccountPassword    = $DomainJoinPassword.SecretValue
    vmAdministratorAccountUsername  = $vmAdministratorAccountUsername
    vmAdministratorAccountPassword  = $vmAdministratorAccountPassword.SecretValue
    vmDiskType                      = $currentVmInfo.StorageProfile.osdisk.ManagedDisk.StorageAccountType
    vmUseManagedDisks               = $true
    createAvailabilitySet           = $false
    hostpooltoken                   = $hostPoolToken
    vmInitialNumber                 = $vmInitialNumber
    vmResourceGroup                 = $resourceGroup
    vmLocation                      = $currentVmInfo.Location
    vmSize                          = $currentVmInfo.HardwareProfile.vmsize
    vmNumberOfInstances             = "2"
    createNetworkSecurityGroup      = $false
    vmCustomImageSourceId           = $latestImageVersion.id
    availabilitySetTags             = $tags
    networkInterfaceTags            = $tags
    networkSecurityGroupTags        = $tags
    virtualMachineTags              = $tags
    imageTags                       = $tags
    aadJoin                         = $false
    intune                          = $false
}

$templateParameters
Clear-Host
Write-Host "Deploying $rdshPrefix"
$deploy = new-AzresourcegroupDeployment -TemplateUri "https://raw.githubusercontent.com/knowledgebaseit/AVD/main/Update/AddSessionHostTemplate.json" @templateParameters -Name "deploy-version-$($latestImageVersion.Name)"

# Get current sessionhost information
$sessionHosts = Get-AzWvdSessionHost -ResourceGroupName $resourceGroup -HostPoolName $hostpool.name
# Get latest sessionhost
$sessionHost1 = $sessionHosts[2]
$sessionHost3 = $sessionHosts[3]
$sessionHostName2 = $sessionHost1.name.Split("/")[-1]
$sessionHostName3 = $sessionHost3.name.Split("/")[-1]

Write-Host "Set $sessionHostName2 on Drain mode"
Update-AzWvdSessionHost -HostPoolName $Hostpoolname -ResourceGroupName $ResourceGroup -Name $sessionHostName2 -AllowNewSession:$false
Write-Host "Set $sessionHostName3 on Drain mode"
Update-AzWvdSessionHost -HostPoolName $Hostpoolname -ResourceGroupName $ResourceGroup -Name $sessionHostName3 -AllowNewSession:$false

Clear-Host
Write-warning "Alle AVD's zijn gedeployed"
