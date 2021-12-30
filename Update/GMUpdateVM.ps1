#Requires -RunAsAdministrator
#Requires -Version 7.0.7

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

# To suppress these warning messages
Set-Item Env:\SuppressAzurePowerShellBreakingChangeWarnings "true"

## NL IMAGE
$UpdateRG = "NLUpdateRG"
$hostpoolName = "AVD-NL"
# Get-TimeZone
$TimeZone = Get-TimeZone
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
$rdshPrefix = $prefix0 + "-" + $prefix1 + "-" + "Update"
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
$DomainJoinPassword = Get-AzKeyVaultSecret -VaultName $GetAzKeyVault.VaultName -Name DomainJoinPassword -AsPlainText
#LocalAdmin
$vmAdministratorAccountUsername = Get-AzKeyVaultSecret -VaultName $GetAzKeyVault.VaultName -Name LocalAdminUser -AsPlainText
$vmAdministratorAccountPassword = Get-AzKeyVaultSecret -VaultName $GetAzKeyVault.VaultName -Name "LocalAdminPassword"
$vmAdministratorCredential = New-Object System.Management.Automation.PSCredential ($vmAdministratorAccountUsername, $vmAdministratorAccountPassword.SecretValue)
# Create resource group
if ($null -eq (Get-AzResourceGroup -Name $UpdateRG -ErrorAction SilentlyContinue)) 
{
    New-AzResourceGroup -Name $UpdateRG -Location $currentVmInfo.Location
}else 
{
    Remove-AzResourceGroup -Name $UpdateRG -Force    
}
if ($null -eq (Get-AzResourceGroup -Name $UpdateRG -ErrorAction SilentlyContinue)) 
{
    New-AzResourceGroup -Name $UpdateRG -Location $currentVmInfo.Location
}
# Create NIC
$NewNIC = New-AzNetworkInterface -Name "$rdshPrefix-nic" -ResourceGroupName $UpdateRG -Location $currentVmInfo.Location -SubnetId $subnetId
$NIC = Get-AzNetworkInterface -Name "$rdshPrefix-nic" -ResourceGroupName $UpdateRG

# Option Public IP
<#
$pip = New-AzPublicIpAddress -Name "$rdshPrefix-pip" -ResourceGroupName $UpdateRG -Location $currentVmInfo.Location -AllocationMethod Static -Sku Basic
$NIC | Set-AzNetworkInterfaceIpConfig -Name $NICIPConfigName -SubnetId $SubnetId -PublicIpAddressId $pip.id | Set-AzNetworkInterface
#>

# IP Config Name to be used with Set-AzNetworkInterfaceIpConfig CmdLet
$NICIPConfigName = $NIC.ipConfigurations[0].Name

# Set NetworkConfig
$NIC | Set-AzNetworkInterfaceIpConfig -Name $NICIPConfigName -SubnetId $SubnetId | Set-AzNetworkInterface
$NIC | Set-AzNetworkInterface

Clear-Host

# Set AzVMConfig
$VirtualMachine = New-AzVMConfig -VMName $rdshPrefix -VMSize $currentVmInfo.HardwareProfile.vmsize
$VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName $rdshPrefix -Credential $vmAdministratorCredential -ProvisionVMAgent -EnableAutoUpdate -TimeZone $TimeZone.id
$VirtualMachine = Add-AzVMNetworkInterface -VM $VirtualMachine -Id $NewNIC.Id
#$VirtualMachine = Set-AzVMOSDisk -Windows -VM $VirtualMachine -CreateOption FromImage -DiskSizeInGB $DiskSizeGB
$VirtualMachine = Set-AzVMBootDiagnostic -VM $VirtualMachine -Disable
$VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -Id $latestImageVersion.id
Clear-Host
# Create Az VM
Write-Host "Creating $rdshPrefix"
New-AzVM -ResourceGroupName $UpdateRG -Location $currentVmInfo.Location -VM $VirtualMachine -DisableBginfoExtension

function Check-VMstatus($VMName) {
    $vmStatus = (Get-AzVM -ResourceGroupName $UpdateRG -Name $rdshPrefix -Status).Statuses
    return $PowerState = $vmStatus[1].DisplayStatus
}

# After creating vm check if vm is running
do {
    $status = Check-VMstatus -VMName $rdshPrefix
    $status
Start-Sleep 15
} until ($status -eq "VM running")


$EnableAutomaticUpgrade = @{
    ExtensionName           = "Microsoft.Azure.Monitoring.DependencyAgent"
    ResourceGroupName       = $UpdateRG
    VMName                  = $rdshPrefix
    Publisher               = "Microsoft.Azure.Monitoring.DependencyAgent"
    ExtensionType           = "DependencyAgentWindows"
    TypeHandlerVersion      = "9.5"
    location                = $currentVmInfo.Location
    EnableAutomaticUpgrade  = $true
}
Set-AzVMExtension @EnableAutomaticUpgrade
Clear-Host
Write-Host "EnableAutomaticUpgrade installed"

$domainJoinSettings = @{
    Name                   = "joindomain"
    Type                   = "JsonADDomainExtension" 
    Publisher              = "Microsoft.Compute"
    typeHandlerVersion     = "1.3"
    SettingString          = '{
        "name": "'+ $($domain) + '",
        "ouPath": "'+ $($ouPath) + '",
        "user": "'+ $($DomainJoinUsername) + '",
        "restart": "'+ $true + '",
        "options": 3
    }'
    ProtectedSettingString = '{
        "Password":"' + $($DomainJoinPassword) + '"}'
    VMName                 = $rdshPrefix
    ResourceGroupName      = $UpdateRG
    location               = $currentVmInfo.Location
}
Set-AzVMExtension @domainJoinSettings
Clear-Host
Write-Host "VM is domain joined installed"

# Update Windows
$blobUri = "https://storagegm.blob.core.windows.net/windows-update/windows-update.ps1"
$FileName = "windows-update.ps1"
$windowsupdate =@{
    Name                    = "windows-update"
    ResourceGroupName       = $UpdateRG
    VMName                  = $rdshPrefix
    location                = $currentVmInfo.Location
    FileUri                 = $blobUri
    Run                     = $FileName
}
Set-AzVMCustomScriptExtension @windowsupdate
Clear-Host
Write-Host "VM is updated"

Restart-AzVM -ResourceGroupName $UpdateRG -Name $rdshPrefix

Write-Host "Remove-AzVMExtension"
Get-AzVMExtension -ResourceGroupName $UpdateRG -VMName $rdshPrefix  | where {$_.ExtensionType -eq "CustomScriptExtension"} | Remove-AzVMExtension -Force

# After sysprep check if vm is running
do {
    $status = Check-vmStatus -VMName $rdshPrefix
    $status
Start-Sleep 10
} until ($status -eq "VM running")

Clear-Host
## END NL

## PL IMAGE
$UpdateRG = "PLUpdateRG"
$hostpoolName = "AVD-PL"
# Get-TimeZone
$TimeZone = Get-TimeZone
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
$rdshPrefix = $prefix0 + "-" + $prefix1 + "-" + "Update"
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
$DomainJoinPassword = Get-AzKeyVaultSecret -VaultName $GetAzKeyVault.VaultName -Name DomainJoinPassword -AsPlainText
#LocalAdmin
$vmAdministratorAccountUsername = Get-AzKeyVaultSecret -VaultName $GetAzKeyVault.VaultName -Name LocalAdminUser -AsPlainText
$vmAdministratorAccountPassword = Get-AzKeyVaultSecret -VaultName $GetAzKeyVault.VaultName -Name "LocalAdminPassword"
$vmAdministratorCredential = New-Object System.Management.Automation.PSCredential ($vmAdministratorAccountUsername, $vmAdministratorAccountPassword.SecretValue)
# Create resource group
if ($null -eq (Get-AzResourceGroup -Name $UpdateRG -ErrorAction SilentlyContinue)) 
{
    New-AzResourceGroup -Name $UpdateRG -Location $currentVmInfo.Location
}else 
{
    Remove-AzResourceGroup -Name $UpdateRG -Force    
}
if ($null -eq (Get-AzResourceGroup -Name $UpdateRG -ErrorAction SilentlyContinue)) 
{
    New-AzResourceGroup -Name $UpdateRG -Location $currentVmInfo.Location
}
# Create NIC
$NewNIC = New-AzNetworkInterface -Name "$rdshPrefix-nic" -ResourceGroupName $UpdateRG -Location $currentVmInfo.Location -SubnetId $subnetId
$NIC = Get-AzNetworkInterface -Name "$rdshPrefix-nic" -ResourceGroupName $UpdateRG

# Option Public IP
<#
$pip = New-AzPublicIpAddress -Name "$rdshPrefix-pip" -ResourceGroupName $UpdateRG -Location $currentVmInfo.Location -AllocationMethod Static -Sku Basic
$NIC | Set-AzNetworkInterfaceIpConfig -Name $NICIPConfigName -SubnetId $SubnetId -PublicIpAddressId $pip.id | Set-AzNetworkInterface
#>

# IP Config Name to be used with Set-AzNetworkInterfaceIpConfig CmdLet
$NICIPConfigName = $NIC.ipConfigurations[0].Name

# Set NetworkConfig
$NIC | Set-AzNetworkInterfaceIpConfig -Name $NICIPConfigName -SubnetId $SubnetId | Set-AzNetworkInterface
$NIC | Set-AzNetworkInterface

Clear-Host

# Set AzVMConfig
$VirtualMachine = New-AzVMConfig -VMName $rdshPrefix -VMSize $currentVmInfo.HardwareProfile.vmsize
$VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName $rdshPrefix -Credential $vmAdministratorCredential -ProvisionVMAgent -EnableAutoUpdate -TimeZone $TimeZone.id
$VirtualMachine = Add-AzVMNetworkInterface -VM $VirtualMachine -Id $NewNIC.Id
#$VirtualMachine = Set-AzVMOSDisk -Windows -VM $VirtualMachine -CreateOption FromImage -DiskSizeInGB $DiskSizeGB
$VirtualMachine = Set-AzVMBootDiagnostic -VM $VirtualMachine -Disable
$VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -Id $latestImageVersion.id
Clear-Host
# Create Az VM
Write-Host "Creating $rdshPrefix"
New-AzVM -ResourceGroupName $UpdateRG -Location $currentVmInfo.Location -VM $VirtualMachine -DisableBginfoExtension

function Check-VMstatus($VMName) {
    $vmStatus = (Get-AzVM -ResourceGroupName $UpdateRG -Name $rdshPrefix -Status).Statuses
    return $PowerState = $vmStatus[1].DisplayStatus
}

# After creating vm check if vm is running
do {
    $status = Check-VMstatus -VMName $rdshPrefix
    $status
Start-Sleep 15
} until ($status -eq "VM running")


$EnableAutomaticUpgrade = @{
    ExtensionName           = "Microsoft.Azure.Monitoring.DependencyAgent"
    ResourceGroupName       = $UpdateRG
    VMName                  = $rdshPrefix
    Publisher               = "Microsoft.Azure.Monitoring.DependencyAgent"
    ExtensionType           = "DependencyAgentWindows"
    TypeHandlerVersion      = "9.5"
    location                = $currentVmInfo.Location
    EnableAutomaticUpgrade  = $true
}
Set-AzVMExtension @EnableAutomaticUpgrade
Clear-Host
Write-Host "EnableAutomaticUpgrade installed"

$domainJoinSettings = @{
    Name                   = "joindomain"
    Type                   = "JsonADDomainExtension" 
    Publisher              = "Microsoft.Compute"
    typeHandlerVersion     = "1.3"
    SettingString          = '{
        "name": "'+ $($domain) + '",
        "ouPath": "'+ $($ouPath) + '",
        "user": "'+ $($DomainJoinUsername) + '",
        "restart": "'+ $true + '",
        "options": 3
    }'
    ProtectedSettingString = '{
        "Password":"' + $($DomainJoinPassword) + '"}'
    VMName                 = $rdshPrefix
    ResourceGroupName      = $UpdateRG
    location               = $currentVmInfo.Location
}
Set-AzVMExtension @domainJoinSettings
Clear-Host
Write-Host "VM is domain joined installed"

# Update Windows
$blobUri = "https://storagegm.blob.core.windows.net/windows-update/windows-update.ps1"
$FileName = "windows-update.ps1"
$windowsupdate =@{
    Name                    = "windows-update"
    ResourceGroupName       = $UpdateRG
    VMName                  = $rdshPrefix
    location                = $currentVmInfo.Location
    FileUri                 = $blobUri
    Run                     = $FileName
}
Set-AzVMCustomScriptExtension @windowsupdate
Clear-Host
Write-Host "VM is updated"

Restart-AzVM -ResourceGroupName $UpdateRG -Name $rdshPrefix

Write-Host "Remove-AzVMExtension"
Get-AzVMExtension -ResourceGroupName $UpdateRG -VMName $rdshPrefix  | where {$_.ExtensionType -eq "CustomScriptExtension"} | Remove-AzVMExtension -Force

# After sysprep check if vm is running
do {
    $status = Check-vmStatus -VMName $rdshPrefix
    $status
Start-Sleep 10
} until ($status -eq "VM running")

Clear-Host
## END PL

## RO IMAGE
$UpdateRG = "ROUpdateRG"
$hostpoolName = "AVD-RO"
# Get-TimeZone
$TimeZone = Get-TimeZone
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
$rdshPrefix = $prefix0 + "-" + $prefix1 + "-" + "Update"
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
$DomainJoinPassword = Get-AzKeyVaultSecret -VaultName $GetAzKeyVault.VaultName -Name DomainJoinPassword -AsPlainText
#LocalAdmin
$vmAdministratorAccountUsername = Get-AzKeyVaultSecret -VaultName $GetAzKeyVault.VaultName -Name LocalAdminUser -AsPlainText
$vmAdministratorAccountPassword = Get-AzKeyVaultSecret -VaultName $GetAzKeyVault.VaultName -Name "LocalAdminPassword"
$vmAdministratorCredential = New-Object System.Management.Automation.PSCredential ($vmAdministratorAccountUsername, $vmAdministratorAccountPassword.SecretValue)
# Create resource group
if ($null -eq (Get-AzResourceGroup -Name $UpdateRG -ErrorAction SilentlyContinue)) 
{
    New-AzResourceGroup -Name $UpdateRG -Location $currentVmInfo.Location
}else 
{
    Remove-AzResourceGroup -Name $UpdateRG -Force    
}
if ($null -eq (Get-AzResourceGroup -Name $UpdateRG -ErrorAction SilentlyContinue)) 
{
    New-AzResourceGroup -Name $UpdateRG -Location $currentVmInfo.Location
}
# Create NIC
$NewNIC = New-AzNetworkInterface -Name "$rdshPrefix-nic" -ResourceGroupName $UpdateRG -Location $currentVmInfo.Location -SubnetId $subnetId
$NIC = Get-AzNetworkInterface -Name "$rdshPrefix-nic" -ResourceGroupName $UpdateRG

# Option Public IP
<#
$pip = New-AzPublicIpAddress -Name "$rdshPrefix-pip" -ResourceGroupName $UpdateRG -Location $currentVmInfo.Location -AllocationMethod Static -Sku Basic
$NIC | Set-AzNetworkInterfaceIpConfig -Name $NICIPConfigName -SubnetId $SubnetId -PublicIpAddressId $pip.id | Set-AzNetworkInterface
#>

# IP Config Name to be used with Set-AzNetworkInterfaceIpConfig CmdLet
$NICIPConfigName = $NIC.ipConfigurations[0].Name

# Set NetworkConfig
$NIC | Set-AzNetworkInterfaceIpConfig -Name $NICIPConfigName -SubnetId $SubnetId | Set-AzNetworkInterface
$NIC | Set-AzNetworkInterface

Clear-Host

# Set AzVMConfig
$VirtualMachine = New-AzVMConfig -VMName $rdshPrefix -VMSize $currentVmInfo.HardwareProfile.vmsize
$VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName $rdshPrefix -Credential $vmAdministratorCredential -ProvisionVMAgent -EnableAutoUpdate -TimeZone $TimeZone.id
$VirtualMachine = Add-AzVMNetworkInterface -VM $VirtualMachine -Id $NewNIC.Id
#$VirtualMachine = Set-AzVMOSDisk -Windows -VM $VirtualMachine -CreateOption FromImage -DiskSizeInGB $DiskSizeGB
$VirtualMachine = Set-AzVMBootDiagnostic -VM $VirtualMachine -Disable
$VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -Id $latestImageVersion.id
Clear-Host
# Create Az VM
Write-Host "Creating $rdshPrefix"
New-AzVM -ResourceGroupName $UpdateRG -Location $currentVmInfo.Location -VM $VirtualMachine -DisableBginfoExtension

function Check-VMstatus($VMName) {
    $vmStatus = (Get-AzVM -ResourceGroupName $UpdateRG -Name $rdshPrefix -Status).Statuses
    return $PowerState = $vmStatus[1].DisplayStatus
}

# After creating vm check if vm is running
do {
    $status = Check-VMstatus -VMName $rdshPrefix
    $status
Start-Sleep 15
} until ($status -eq "VM running")


$EnableAutomaticUpgrade = @{
    ExtensionName           = "Microsoft.Azure.Monitoring.DependencyAgent"
    ResourceGroupName       = $UpdateRG
    VMName                  = $rdshPrefix
    Publisher               = "Microsoft.Azure.Monitoring.DependencyAgent"
    ExtensionType           = "DependencyAgentWindows"
    TypeHandlerVersion      = "9.5"
    location                = $currentVmInfo.Location
    EnableAutomaticUpgrade  = $true
}
Set-AzVMExtension @EnableAutomaticUpgrade
Clear-Host
Write-Host "EnableAutomaticUpgrade installed"

$domainJoinSettings = @{
    Name                   = "joindomain"
    Type                   = "JsonADDomainExtension" 
    Publisher              = "Microsoft.Compute"
    typeHandlerVersion     = "1.3"
    SettingString          = '{
        "name": "'+ $($domain) + '",
        "ouPath": "'+ $($ouPath) + '",
        "user": "'+ $($DomainJoinUsername) + '",
        "restart": "'+ $true + '",
        "options": 3
    }'
    ProtectedSettingString = '{
        "Password":"' + $($DomainJoinPassword) + '"}'
    VMName                 = $rdshPrefix
    ResourceGroupName      = $UpdateRG
    location               = $currentVmInfo.Location
}
Set-AzVMExtension @domainJoinSettings
Clear-Host
Write-Host "VM is domain joined installed"

# Update Windows
$blobUri = "https://storagegm.blob.core.windows.net/windows-update/windows-update.ps1"
$FileName = "windows-update.ps1"
$windowsupdate =@{
    Name                    = "windows-update"
    ResourceGroupName       = $UpdateRG
    VMName                  = $rdshPrefix
    location                = $currentVmInfo.Location
    FileUri                 = $blobUri
    Run                     = $FileName
}
Set-AzVMCustomScriptExtension @windowsupdate
Clear-Host
Write-Host "VM is updated"

Restart-AzVM -ResourceGroupName $UpdateRG -Name $rdshPrefix

Write-Host "Remove-AzVMExtension"
Get-AzVMExtension -ResourceGroupName $UpdateRG -VMName $rdshPrefix  | where {$_.ExtensionType -eq "CustomScriptExtension"} | Remove-AzVMExtension -Force

# After sysprep check if vm is running
do {
    $status = Check-vmStatus -VMName $rdshPrefix
    $status
Start-Sleep 10
} until ($status -eq "VM running")

Clear-Host

## END RO

## UA IMAGE
$UpdateRG = "UAUpdateRG"
$hostpoolName = "AVD-UA"
# Get-TimeZone
$TimeZone = Get-TimeZone
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
$rdshPrefix = $prefix0 + "-" + $prefix1 + "-" + "Update"
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
$DomainJoinPassword = Get-AzKeyVaultSecret -VaultName $GetAzKeyVault.VaultName -Name DomainJoinPassword -AsPlainText
#LocalAdmin
$vmAdministratorAccountUsername = Get-AzKeyVaultSecret -VaultName $GetAzKeyVault.VaultName -Name LocalAdminUser -AsPlainText
$vmAdministratorAccountPassword = Get-AzKeyVaultSecret -VaultName $GetAzKeyVault.VaultName -Name "LocalAdminPassword"
$vmAdministratorCredential = New-Object System.Management.Automation.PSCredential ($vmAdministratorAccountUsername, $vmAdministratorAccountPassword.SecretValue)
# Create resource group
if ($null -eq (Get-AzResourceGroup -Name $UpdateRG -ErrorAction SilentlyContinue)) 
{
    New-AzResourceGroup -Name $UpdateRG -Location $currentVmInfo.Location
}else 
{
    Remove-AzResourceGroup -Name $UpdateRG -Force    
}
if ($null -eq (Get-AzResourceGroup -Name $UpdateRG -ErrorAction SilentlyContinue)) 
{
    New-AzResourceGroup -Name $UpdateRG -Location $currentVmInfo.Location
}
# Create NIC
$NewNIC = New-AzNetworkInterface -Name "$rdshPrefix-nic" -ResourceGroupName $UpdateRG -Location $currentVmInfo.Location -SubnetId $subnetId
$NIC = Get-AzNetworkInterface -Name "$rdshPrefix-nic" -ResourceGroupName $UpdateRG

# Option Public IP
<#
$pip = New-AzPublicIpAddress -Name "$rdshPrefix-pip" -ResourceGroupName $UpdateRG -Location $currentVmInfo.Location -AllocationMethod Static -Sku Basic
$NIC | Set-AzNetworkInterfaceIpConfig -Name $NICIPConfigName -SubnetId $SubnetId -PublicIpAddressId $pip.id | Set-AzNetworkInterface
#>

# IP Config Name to be used with Set-AzNetworkInterfaceIpConfig CmdLet
$NICIPConfigName = $NIC.ipConfigurations[0].Name

# Set NetworkConfig
$NIC | Set-AzNetworkInterfaceIpConfig -Name $NICIPConfigName -SubnetId $SubnetId | Set-AzNetworkInterface
$NIC | Set-AzNetworkInterface

Clear-Host

# Set AzVMConfig
$VirtualMachine = New-AzVMConfig -VMName $rdshPrefix -VMSize $currentVmInfo.HardwareProfile.vmsize
$VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName $rdshPrefix -Credential $vmAdministratorCredential -ProvisionVMAgent -EnableAutoUpdate -TimeZone $TimeZone.id
$VirtualMachine = Add-AzVMNetworkInterface -VM $VirtualMachine -Id $NewNIC.Id
#$VirtualMachine = Set-AzVMOSDisk -Windows -VM $VirtualMachine -CreateOption FromImage -DiskSizeInGB $DiskSizeGB
$VirtualMachine = Set-AzVMBootDiagnostic -VM $VirtualMachine -Disable
$VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -Id $latestImageVersion.id
Clear-Host
# Create Az VM
Write-Host "Creating $rdshPrefix"
New-AzVM -ResourceGroupName $UpdateRG -Location $currentVmInfo.Location -VM $VirtualMachine -DisableBginfoExtension

function Check-VMstatus($VMName) {
    $vmStatus = (Get-AzVM -ResourceGroupName $UpdateRG -Name $rdshPrefix -Status).Statuses
    return $PowerState = $vmStatus[1].DisplayStatus
}

# After creating vm check if vm is running
do {
    $status = Check-VMstatus -VMName $rdshPrefix
    $status
Start-Sleep 15
} until ($status -eq "VM running")


$EnableAutomaticUpgrade = @{
    ExtensionName           = "Microsoft.Azure.Monitoring.DependencyAgent"
    ResourceGroupName       = $UpdateRG
    VMName                  = $rdshPrefix
    Publisher               = "Microsoft.Azure.Monitoring.DependencyAgent"
    ExtensionType           = "DependencyAgentWindows"
    TypeHandlerVersion      = "9.5"
    location                = $currentVmInfo.Location
    EnableAutomaticUpgrade  = $true
}
Set-AzVMExtension @EnableAutomaticUpgrade
Clear-Host
Write-Host "EnableAutomaticUpgrade installed"

$domainJoinSettings = @{
    Name                   = "joindomain"
    Type                   = "JsonADDomainExtension" 
    Publisher              = "Microsoft.Compute"
    typeHandlerVersion     = "1.3"
    SettingString          = '{
        "name": "'+ $($domain) + '",
        "ouPath": "'+ $($ouPath) + '",
        "user": "'+ $($DomainJoinUsername) + '",
        "restart": "'+ $true + '",
        "options": 3
    }'
    ProtectedSettingString = '{
        "Password":"' + $($DomainJoinPassword) + '"}'
    VMName                 = $rdshPrefix
    ResourceGroupName      = $UpdateRG
    location               = $currentVmInfo.Location
}
Set-AzVMExtension @domainJoinSettings
Clear-Host
Write-Host "VM is domain joined installed"

# Update Windows
$blobUri = "https://storagegm.blob.core.windows.net/windows-update/windows-update.ps1"
$FileName = "windows-update.ps1"
$windowsupdate =@{
    Name                    = "windows-update"
    ResourceGroupName       = $UpdateRG
    VMName                  = $rdshPrefix
    location                = $currentVmInfo.Location
    FileUri                 = $blobUri
    Run                     = $FileName
}
Set-AzVMCustomScriptExtension @windowsupdate
Clear-Host
Write-Host "VM is updated"

Restart-AzVM -ResourceGroupName $UpdateRG -Name $rdshPrefix

Write-Host "Remove-AzVMExtension"
Get-AzVMExtension -ResourceGroupName $UpdateRG -VMName $rdshPrefix  | where {$_.ExtensionType -eq "CustomScriptExtension"} | Remove-AzVMExtension -Force

# After sysprep check if vm is running
do {
    $status = Check-vmStatus -VMName $rdshPrefix
    $status
Start-Sleep 10
} until ($status -eq "VM running")

Clear-Host
## End UA

Write-Host "Stap 1: In Azure alle update (interne) RDP Downloaden"
