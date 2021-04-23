#################################################################################################
#    ______    __                     __         __ __ _      ___            
#   / ____/___/ /_  ______ __________/ /___     / //_/(_)__  / (_)___  ____ _
#  / __/ / __  / / / / __ `/ ___/ __  / __ \   / ,<  / / _ \/ / / __ \/ __ `/
# / /___/ /_/ / /_/ / /_/ / /  / /_/ / /_/ /  / /| |/ /  __/ / / / / / /_/ / 
#/_____/\__,_/\__,_/\__,_/_/   \__,_/\____/  /_/ |_/_/\___/_/_/_/ /_/\__, /  
#                                                                   /____/   
#
#Blog: Https://eduardokieling.com
#LinkedIn: https://www.linkedin.com/in/eduardokieling
#Microsoft Azure MVP
#################################################################################################
#
#
#
####################################################################################
####################################################################################
#
#>>>>>>>>REGION 1 - PRIMARY Site (HUB SPOKE TOPOLOGY)
#
####################################################################################
####################################################################################
#
#
#
#
##########################################
###------------------------------------###
#______(HUB environment - SITE_1)______###
###------------------------------------###
##########################################
#
#

# Create a HUB resource group - SITE_1
resource "azurerm_resource_group" "rg_prd_hub_1" {
  name     = "${var.company_name}-RGPRD-HUB-${var.infra_location_Abreviation_1}"
  location = var.infra_location_1
}

# Lock a PRD Resource Group - SITE_1
resource "azurerm_management_lock" "lock_prd_hub_1" {
  name       = "Lock_${azurerm_resource_group.rg_prd_hub_1.name}"
  scope      = azurerm_resource_group.rg_prd_hub_1.id
  lock_level = "CanNotDelete"
  notes      = "This Resource Group cannot be Deleted"
  depends_on = [azurerm_resource_group.rg_prd_hub_1]
}

# Create a HUB storage account for diagnostics - SITE_1
resource "azurerm_storage_account" "stg_diag_hub_1" {
  name                     = lower("storage${var.company_name}${var.infra_location_Abreviation_1}hubdiag")
  resource_group_name      = azurerm_resource_group.rg_prd_hub_1.name
  location                 = var.infra_location_1
  account_replication_type = "LRS"
  account_tier             = "Standard"
  account_kind             = "StorageV2"
  enable_https_traffic_only = true
}

# Create a MANAGEMENT Network Security Group and Rules - SITE_1
resource "azurerm_network_security_group" "nsg_prd_management_1" {
  name                = upper("NSG-MANAGEMENT-${var.infra_location_Abreviation_1}")
  location            = var.infra_location_1
  resource_group_name = azurerm_resource_group.rg_prd_hub_1.name

  security_rule {
    name                       = "Allow_Access_SOUCLOUD_1"
    priority                   = 131
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "186.237.28.64/28"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow_Access_SOUCLOUD_2"
    priority                   = 132
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "186.237.31.154"
    destination_address_prefix = "*"
  }

  
  security_rule {
    name                       = "Allow_Access_SOUCLOUD_3"
    priority                   = 133
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "13.91.94.50"
    destination_address_prefix = "*"
  }


  security_rule {
    name                       = "Allow_Access_VPN_PTS"
    priority                   = 134
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "${var.prd_vpn_pts_network_1}/24"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow_Access_Management_RDP"
    priority                   = 135
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "TCP"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "${var.prd_management_network_1}/24"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow_Access_Management_SSH"
    priority                   = 136
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "TCP"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "${var.prd_management_network_1}/24"
    destination_address_prefix = "*"
  }
}

# Create a DMZ Network Security Group and Rules - SITE_1
resource "azurerm_network_security_group" "nsg_prd_dmz_1" {
  name                = upper("NSG-DMZ-${var.infra_location_Abreviation_1}")
  location            = var.infra_location_1
  resource_group_name = azurerm_resource_group.rg_prd_hub_1.name

  security_rule {
    name                       = "Allow_Access_Management_RDP"
    priority                   = 131
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "TCP"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "${var.prd_management_network_1}/24"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow_Access_Management_SSH"
    priority                   = 132
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "TCP"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "${var.prd_management_network_1}/24"
    destination_address_prefix = "*"
  }

}

# Create a HUB Virtual Network - SITE_1
resource "azurerm_virtual_network" "vnet_prd_hub_1" {
  name                = upper("VNET-${azurerm_resource_group.rg_prd_hub_1.name}")
  address_space       = ["${var.prd_hub_network_1}/18"]
  location            = var.infra_location_1
  resource_group_name = azurerm_resource_group.rg_prd_hub_1.name
}

# Create a MANAGEMENT Subnet - SITE_1
resource "azurerm_subnet" "subnet_prd_management_1" {
  name                 = lower("${var.infra_location_Abreviation_1}-prd_management_subnet")
  resource_group_name  = azurerm_resource_group.rg_prd_hub_1.name
  virtual_network_name = azurerm_virtual_network.vnet_prd_hub_1.name
  address_prefixes       = ["${var.prd_management_network_1}/24"]
}

# Create a BASTION Subnet - SITE_1
resource "azurerm_subnet" "subnet_bastion_1" {
  name                 = "AzureBastionSubnet"
  resource_group_name  = azurerm_resource_group.rg_prd_hub_1.name
  virtual_network_name = azurerm_virtual_network.vnet_prd_hub_1.name
  address_prefixes       = ["${var.prd_bastion_network_1}/27"]
}

# Create a DMZ Subnet - SITE_1
resource "azurerm_subnet" "subnet_prd_dmz_1" {
  name                 = lower("${var.infra_location_Abreviation_1}-prd_dmz_subnet")
  resource_group_name  = azurerm_resource_group.rg_prd_hub_1.name
  virtual_network_name = azurerm_virtual_network.vnet_prd_hub_1.name
  address_prefixes       = ["${var.prd_dmz_network_1}/24"]
}

# Create a VPN Subnet - SITE_1
resource "azurerm_subnet" "subnet_vpn_1" {
  name                 = "GatewaySubnet"
  resource_group_name  = azurerm_resource_group.rg_prd_hub_1.name
  virtual_network_name = azurerm_virtual_network.vnet_prd_hub_1.name
  address_prefixes       = ["${var.prd_vpn_network_1}/24"]
}

# Create a Firewall Subnet - PRD
resource "azurerm_subnet" "subnet_firewall" {
  name                 = "AzureFirewallSubnet"
  resource_group_name  = azurerm_resource_group.rg_prd_hub_1.name
  virtual_network_name = azurerm_virtual_network.vnet_prd_hub_1.name
  address_prefixes       = ["${var.prd_firewall_subnet_1}/24"]
}

# Create a Application Gateway Subnet - PRD
resource "azurerm_subnet" "subnet_apg" {
  name                 = lower("${var.infra_location_Abreviation_1}-prd_apg_subnet")
  resource_group_name  = azurerm_resource_group.rg_prd_hub_1.name
  virtual_network_name = azurerm_virtual_network.vnet_prd_hub_1.name
  address_prefixes       = ["${var.prd_applicationgateway_subnet_1}/24"]
}

# Associate a MANAGEMENT Network Security Group - SITE_1
resource "azurerm_subnet_network_security_group_association" "nsgassociation-prd_management_1" {
  subnet_id                 = azurerm_subnet.subnet_prd_management_1.id
  network_security_group_id = azurerm_network_security_group.nsg_prd_management_1.id
}

# Associate a DMZ Network Security Group - SITE_1
resource "azurerm_subnet_network_security_group_association" "nsgassociation-prd_dmz_1" {
  subnet_id                 = azurerm_subnet.subnet_prd_dmz_1.id
  network_security_group_id = azurerm_network_security_group.nsg_prd_dmz_1.id
}


# Create a BASTION Public IP - SITE_1
resource "azurerm_public_ip" "bastion_public_ip_1" {
  name                = "IPP-BAS-${azurerm_resource_group.rg_prd_hub_1.name}"
  location            = var.infra_location_1
  resource_group_name = azurerm_resource_group.rg_prd_hub_1.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

# Create a BASTION Host - SITE_1
resource "azurerm_bastion_host" "bastion_host_1" {
  name                = upper("BAS-${azurerm_resource_group.rg_prd_hub_1.name}")
  location            = var.infra_location_1
  resource_group_name = azurerm_resource_group.rg_prd_hub_1.name

  ip_configuration {
    name                 = "bastion_configuration_1"
    subnet_id            = azurerm_subnet.subnet_bastion_1.id
    public_ip_address_id = azurerm_public_ip.bastion_public_ip_1.id
  }
}

###########CREATE JUMPBOX##############

#Create a VM Public IP - SITE_1
resource "azurerm_public_ip" "ipp_vmw_jumpbox_1" {
  name                = "IPP-JUMPBOX"
  location            = var.infra_location_1
  resource_group_name = azurerm_resource_group.rg_prd_hub_1.name
  allocation_method   = "Static"
}

#Create a Nic Interface - SITE_1
resource "azurerm_network_interface" "nic_vmw_jumpbox_1" {
  name                      = "VMWJMPAZPRD01NIC01"
  location                  = var.infra_location_1
  resource_group_name       = azurerm_resource_group.rg_prd_hub_1.name
  depends_on                = [azurerm_subnet.subnet_prd_management_1]
  
  ip_configuration {
    name                          = "VMWJMPAZPRD01NicConfiguration"
    subnet_id                     = azurerm_subnet.subnet_prd_management_1.id
    private_ip_address_allocation = "Static"
    private_ip_address            = var.prd_jumbox_ip_1
    public_ip_address_id          = azurerm_public_ip.ipp_vmw_jumpbox_1.id
  }
}

# Create a Proximity Placement Group - SITE_1
resource "azurerm_proximity_placement_group" "ppg_hub_1" {
  name                = upper("PPG-${azurerm_resource_group.rg_prd_hub_1.name}")
  location            = var.infra_location_1
  resource_group_name = azurerm_resource_group.rg_prd_hub_1.name
}

# Create a Availability Set - SITE_1
resource "azurerm_availability_set" "has_vmw_jumpbox_1" {
  name                = upper("HAS-${azurerm_resource_group.rg_prd_hub_1.name}")
  location            = var.infra_location_1
  resource_group_name = azurerm_resource_group.rg_prd_hub_1.name
  platform_fault_domain_count = 2

  proximity_placement_group_id = azurerm_proximity_placement_group.ppg_hub_1.id
}

# Accept CIS Terms
resource "azurerm_marketplace_agreement" "cisterms2" {
  publisher = "center-for-internet-security-inc"
  offer     = "cis-windows-server-2019-v1-0-0-l1"
  plan      = "cis-ws2019-l1"
} 

# Create a Virtual Machine - SITE_1
resource "azurerm_virtual_machine" "vm_vmw_jumpbox_1" {
  name                  = "VMW-JMP-AZPRD01"
  location              = var.infra_location_1
  resource_group_name   = azurerm_resource_group.rg_prd_hub_1.name
  network_interface_ids = [azurerm_network_interface.nic_vmw_jumpbox_1.id]
  vm_size               = "Standard_D4as_v4"
  availability_set_id = azurerm_availability_set.has_vmw_jumpbox_1.id

  delete_os_disk_on_termination    = true
  delete_data_disks_on_termination = true

  plan {
    publisher = "center-for-internet-security-inc"
    product     = "cis-windows-server-2019-v1-0-0-l1"
    name      = "cis-ws2019-l1"
  }


  storage_os_disk {
    name              = "VMW-JMP-AZPRD01-OSDISK"
    caching           = "ReadWrite"
    create_option     = "FromImage"
    managed_disk_type = "Standard_LRS"
  }

  storage_image_reference {
    publisher = "center-for-internet-security-inc"
    offer     = "cis-windows-server-2019-v1-0-0-l1"
    sku       = "cis-ws2019-l1"
    version   = "latest"
  }

  os_profile {
    computer_name  = "VMW-JMP-AZPRD01"
    admin_username = var.vmuser
    admin_password = var.vmpw
  }

  os_profile_windows_config {
    provision_vm_agent        = true
    enable_automatic_upgrades = false
  }

  boot_diagnostics {
    enabled     = "true"
    storage_uri = azurerm_storage_account.stg_diag_hub_1.primary_blob_endpoint
  }
}

# Create a Virtual Network Gateway for Basic VPN - SITE_1
resource "azurerm_public_ip" "ippublicovpn01_basic_1" {
  count = var.vpn_enable_bpg_configuration_1 ? 0 : 1
  name                = upper("IPP-VNG-${azurerm_resource_group.rg_prd_hub_1.name}-01")
  location            = var.infra_location_1
  resource_group_name = azurerm_resource_group.rg_prd_hub_1.name
  allocation_method = "Dynamic"
}

resource "azurerm_virtual_network_gateway" "vpn_prd_basic_1" {
  count = var.vpn_enable_bpg_configuration_1 ? 0 : 1
  name                = upper("VNG-${azurerm_resource_group.rg_prd_hub_1.name}-01")
  location            = var.infra_location_1
  resource_group_name = azurerm_resource_group.rg_prd_hub_1.name

  type     = "Vpn"
  vpn_type = "RouteBased"

  active_active = "false"
  enable_bgp    = "false"
  sku           = var.vpn_sku_1

  ip_configuration {
    name                          = "vnetGatewayConfig01_basic_1"
    public_ip_address_id          = azurerm_public_ip.ippublicovpn01_basic_1[count.index].id
    private_ip_address_allocation = "Dynamic"
    subnet_id                     = azurerm_subnet.subnet_vpn_1.id
  }
}

# Create a Virtual Network Gateway for VPN with BGP  - SITE_1
resource "azurerm_public_ip" "ippublicovpn01_bpg_1" {
  count = var.vpn_enable_bpg_configuration_1 ? 1 : 0
  name                = upper("IPP-VNG-${azurerm_resource_group.rg_prd_hub_1.name}-01")
  location            = var.infra_location_1
  resource_group_name = azurerm_resource_group.rg_prd_hub_1.name
  allocation_method = "Dynamic"
}

resource "azurerm_public_ip" "ippublicovpn02_bpg_1" {
  count = var.vpn_enable_bpg_configuration_1 ? 1 : 0
  name                = upper("IPP-VNG-${azurerm_resource_group.rg_prd_hub_1.name}-02")
  location            = var.infra_location_1
  resource_group_name = azurerm_resource_group.rg_prd_hub_1.name
  allocation_method = "Dynamic"
}

resource "azurerm_virtual_network_gateway" "vpn_prd_bpg_1" {
  count = var.vpn_enable_bpg_configuration_1 ? 1 : 0
  name                = upper("VNG-${azurerm_resource_group.rg_prd_hub_1.name}-01")
  location            = var.infra_location_1
  resource_group_name = azurerm_resource_group.rg_prd_hub_1.name

  type     = "Vpn"
  vpn_type = "RouteBased"

  active_active = "true"
  enable_bgp    = "true"
  bgp_settings {
    asn   = 65515
  }
  sku           = var.vpn_sku_1

  ip_configuration {
    name                          = "vnetGatewayConfig01_bpg_1"
    public_ip_address_id          = azurerm_public_ip.ippublicovpn01_bpg_1[count.index].id
    private_ip_address_allocation = "Dynamic"
    subnet_id                     = azurerm_subnet.subnet_vpn_1.id
  }

  ip_configuration {
    name                          = "vnetGatewayConfig02_bpg_1"
    public_ip_address_id          = azurerm_public_ip.ippublicovpn02_bpg_1[count.index].id
    private_ip_address_allocation = "Dynamic"
    subnet_id                     = azurerm_subnet.subnet_vpn_1.id
  }
}

#Azure Firewall  - SITE_1

resource "azurerm_public_ip" "ippazurefirewall" {
  name                = "IPP-AZUREFIREWALL"
  location = var.infra_location_1
  resource_group_name  = azurerm_resource_group.rg_prd_hub_1.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_firewall" "fwazurefirewall" {
  name                = "${var.company_name}-AZFIREWALL"
  location = var.infra_location_1
  resource_group_name  = azurerm_resource_group.rg_prd_hub_1.name

  ip_configuration {
    name                 = "configuration"
    subnet_id            = azurerm_subnet.subnet_firewall.id
    public_ip_address_id = azurerm_public_ip.ippazurefirewall.id
  }
}

# Azure Firewall - App Rule Collection

resource "azurerm_firewall_application_rule_collection" "apprulefwazurefirewall" {
  name                = "allowedcollection"
  azure_firewall_name = azurerm_firewall.fwazurefirewall.name
  resource_group_name  = azurerm_resource_group.rg_prd_hub_1.name
  priority            = 100
  action              = "Allow"

  rule {
    name = "allow-sou.cloud"

    source_addresses = [
      "172.23.15.0/24",
    ]

    target_fqdns = [
      "*.nordcloud.com",
    ]

    protocol {
      port = "443"
      type = "Https"
    }
  }
}

# Azure Firewall - App NAT Rule Collection
resource "azurerm_firewall_nat_rule_collection" "natfwazurefirewall" {
  name                = "natcollection"
  azure_firewall_name = azurerm_firewall.fwazurefirewall.name
  resource_group_name  = azurerm_resource_group.rg_prd_hub_1.name
  priority            = 110
  action              = "Dnat"

  rule {
    name = "dnat_dns"

    source_addresses = [
      "172.23.15.0/24",
    ]

    destination_ports = [
      "53",
    ]

    destination_addresses = [
      azurerm_public_ip.ippazurefirewall.ip_address
    ]

    translated_port = 53

    translated_address = "8.8.8.8"

    protocols = [
      "TCP",
      "UDP",
    ]
  }
}


##########################################
###------------------------------------###
#______(SPOKE environment - SITE_1)____###
###------------------------------------###
##########################################
#
#
#
# Create a PRD resource group - SITE_1
resource "azurerm_resource_group" "rg_prd_1" {
  name     = "${var.company_name}-RGPRD-${var.infra_location_Abreviation_1}"
  location = var.infra_location_1
}

# Lock a PRD Resource Group - SITE_1
resource "azurerm_management_lock" "lock_prd_1" {
  name       = "Lock_${azurerm_resource_group.rg_prd_1.name}"
  scope      = azurerm_resource_group.rg_prd_1.id
  lock_level = "CanNotDelete"
  notes      = "This Resource Group cannot be Deleted"
  depends_on = [azurerm_resource_group.rg_prd_1]
}

# Create a PRD Network Security Group and Rules - SITE_1
resource "azurerm_network_security_group" "nsg_prd_1" {
  name                = upper("NSG-PRD-${var.infra_location_Abreviation_1}")
  location            = var.infra_location_1
  resource_group_name = azurerm_resource_group.rg_prd_1.name

  security_rule {
    name                       = "Allow_Access_SOUCLOUD_1"
    priority                   = 131
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "186.237.28.64/28"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow_Access_SOUCLOUD_2"
    priority                   = 132
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "186.237.31.154"
    destination_address_prefix = "*"
  }

  
  security_rule {
    name                       = "Allow_Access_SOUCLOUD_3"
    priority                   = 133
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "13.91.94.50"
    destination_address_prefix = "*"
  }


  security_rule {
    name                       = "Allow_Access_VPN_PTS"
    priority                   = 134
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "${var.prd_vpn_pts_network_1}/24"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow_Access_Management_RDP"
    priority                   = 135
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "TCP"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "${var.prd_management_network_1}/24"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow_Access_Management_SSH"
    priority                   = 136
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "TCP"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "${var.prd_management_network_1}/24"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Deny_Hub_Network"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "TCP"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "${var.prd_hub_network_1}/17"
    destination_address_prefix = "*"
  }

}

# Create a QAS Network Security Group and Rules - SITE_1
resource "azurerm_network_security_group" "nsg_qas_1" {
  name                = upper("NSG-QAS-${var.infra_location_Abreviation_1}")
  location            = var.infra_location_1
  resource_group_name = azurerm_resource_group.rg_prd_1.name

  security_rule {
    name                       = "Allow_Access_SOUCLOUD_1"
    priority                   = 131
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "186.237.28.64/28"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow_Access_SOUCLOUD_2"
    priority                   = 132
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "186.237.31.154"
    destination_address_prefix = "*"
  }

  
  security_rule {
    name                       = "Allow_Access_SOUCLOUD_3"
    priority                   = 133
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "13.91.94.50"
    destination_address_prefix = "*"
  }


  security_rule {
    name                       = "Allow_Access_VPN_PTS"
    priority                   = 134
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "${var.prd_vpn_pts_network_1}/24"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow_Access_Management_RDP"
    priority                   = 135
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "TCP"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "${var.prd_management_network_1}/24"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow_Access_Management_SSH"
    priority                   = 136
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "TCP"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "${var.prd_management_network_1}/24"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Deny_Hub_Network"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "TCP"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "${var.prd_hub_network_1}/17"
    destination_address_prefix = "*"
  }

}

# Create a DEV Network Security Group and Rules - SITE_1 
resource "azurerm_network_security_group" "nsg_dev_1" {
  name                = upper("NSG-DEV-${var.infra_location_Abreviation_1}")
  location            = var.infra_location_1
  resource_group_name = azurerm_resource_group.rg_prd_1.name

  security_rule {
    name                       = "Allow_Access_SOUCLOUD_1"
    priority                   = 131
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "186.237.28.64/28"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow_Access_SOUCLOUD_2"
    priority                   = 132
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "186.237.31.154"
    destination_address_prefix = "*"
  }

  
  security_rule {
    name                       = "Allow_Access_SOUCLOUD_3"
    priority                   = 133
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "13.91.94.50"
    destination_address_prefix = "*"
  }


  security_rule {
    name                       = "Allow_Access_VPN_PTS"
    priority                   = 134
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "${var.prd_vpn_pts_network_1}/24"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow_Access_Management_RDP"
    priority                   = 135
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "TCP"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "${var.prd_management_network_1}/24"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow_Access_Management_SSH"
    priority                   = 136
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "TCP"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "${var.prd_management_network_1}/24"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Deny_Hub_Network"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "TCP"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "${var.prd_hub_network_1}/17"
    destination_address_prefix = "*"
  }

}

# Create a SPOKE Virtual Network - SITE_1
resource "azurerm_virtual_network" "vnet_prd_1" {
  name                = upper("VNET-${azurerm_resource_group.rg_prd_1.name}")
  address_space       = ["${var.prd_general_network_1}/18"]
  location            = var.infra_location_1
  resource_group_name = azurerm_resource_group.rg_prd_1.name
}

# Create a PRD Subnet - SITE_1
resource "azurerm_subnet" "subnet_prd_1" {
  name                 = lower("${var.infra_location_Abreviation_1}-prd_subnet")
  resource_group_name  = azurerm_resource_group.rg_prd_1.name
  virtual_network_name = azurerm_virtual_network.vnet_prd_1.name
  address_prefixes       = ["${var.prd_general_network_1}/24"]
}

# Create a QAS Subnet - SITE_1
resource "azurerm_subnet" "subnet_qas_1" {
  name                 = lower("${var.infra_location_Abreviation_1}-qa_subnet")
  resource_group_name  = azurerm_resource_group.rg_prd_1.name
  virtual_network_name = azurerm_virtual_network.vnet_prd_1.name
  address_prefixes       = ["${var.qas_general_network_1}/24"]
}

# Create a DEV Subnet - SITE_1
resource "azurerm_subnet" "subnet_dev_1" {
  name                 = lower("${var.infra_location_Abreviation_1}-dev_subnet")
  resource_group_name  = azurerm_resource_group.rg_prd_1.name
  virtual_network_name = azurerm_virtual_network.vnet_prd_1.name
  address_prefixes       = ["${var.dev_general_network_1}/24"]
}

# Associate a PRD Network Security Group - SITE_1
resource "azurerm_subnet_network_security_group_association" "nsgassociation-prd_1" {
  subnet_id                 = azurerm_subnet.subnet_prd_1.id
  network_security_group_id = azurerm_network_security_group.nsg_prd_1.id
}

# Associate a QAS Network Security Group - SITE_1
resource "azurerm_subnet_network_security_group_association" "nsgassociation-qas_1" {
  subnet_id                 = azurerm_subnet.subnet_qas_1.id
  network_security_group_id = azurerm_network_security_group.nsg_qas_1.id
}

# Associate a DEV Network Security Group - SITE_1
resource "azurerm_subnet_network_security_group_association" "nsgassociation-dev_1" {
  subnet_id                 = azurerm_subnet.subnet_dev_1.id
  network_security_group_id = azurerm_network_security_group.nsg_dev_1.id
}

# Create a default Key Vault - SITE_1
resource "azurerm_key_vault" "keyvaultprd01_1" {
  name                = upper("KEY-${var.company_name}-${var.infra_location_Abreviation_1}")
  location            = var.infra_location_1
  resource_group_name = azurerm_resource_group.rg_prd_1.name
  enabled_for_disk_encryption = true
  tenant_id                   = var.azure_tenant_id
  sku_name = "standard"
}

# Create a SPOKE storage account for diagnostics - SITE_1
resource "azurerm_storage_account" "stg_diag_1" {
  name                     = lower("stg${var.company_name}${var.infra_location_Abreviation_1}diag")
  resource_group_name      = azurerm_resource_group.rg_prd_1.name
  location                 = var.infra_location_1
  account_replication_type = "LRS"
  account_tier             = "Standard"
  account_kind             = "StorageV2"
  enable_https_traffic_only = true
}

# Create a Automation Account - SITE_1
resource "azurerm_automation_account" "prd_automation_account_1" {
  name                = upper("AUTO-${azurerm_resource_group.rg_prd_1.name}-01")
  location            = var.infra_location_1
  resource_group_name = azurerm_resource_group.rg_prd_1.name
  sku_name = "Basic"
}

# Create a Log Analytics Workspace - SITE_1
resource "azurerm_log_analytics_workspace" "prd_log_analytics_1" {
  name                = upper("LAW-${azurerm_resource_group.rg_prd_1.name}-01")
  location            = var.infra_location_1
  resource_group_name = azurerm_resource_group.rg_prd_1.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  depends_on          = [azurerm_resource_group.rg_prd_1]
}

# Create a Network Watcher - SITE_1
resource "azurerm_network_watcher" "prd-networkwatcher_1" {
  name                = upper("NW-${azurerm_resource_group.rg_prd_1.name}-01")
  location            = var.infra_location_1
  resource_group_name = azurerm_resource_group.rg_prd_1.name
  depends_on          = [azurerm_log_analytics_workspace.prd_log_analytics_1]
}

/*
# Associate a Network Watcher to Network Security Group - SITE_1
resource "azurerm_network_watcher_flow_log" "nwflow_prd_general_1" {
  network_watcher_name = azurerm_network_watcher.prd-networkwatcher_1.name
  resource_group_name  = azurerm_resource_group.rg_prd_1.name
  depends_on = [azurerm_network_watcher.prd-networkwatcher_1]
  network_security_group_id = azurerm_network_security_group.nsg_prd_1.id
  storage_account_id        = azurerm_storage_account.stg_diag_1.id
  enabled                   = true

  retention_policy {
    enabled = true
    days    = 7
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.prd_log_analytics_1.workspace_id
    workspace_region      = azurerm_log_analytics_workspace.prd_log_analytics_1.location
    workspace_resource_id = azurerm_log_analytics_workspace.prd_log_analytics_1.id
  }
}
*/

# Create a Recovery Services Vault - SITE_1
resource "azurerm_recovery_services_vault" "vault_prd_1" {
  name                = upper("RSV-${azurerm_resource_group.rg_prd_1.name}-01")
  location            = var.infra_location_1
  resource_group_name = azurerm_resource_group.rg_prd_1.name
  sku                 = "Standard"
  soft_delete_enabled = "true"
}

# Create a Recovery Services Protection Policy - SITE_1
resource "azurerm_backup_policy_vm" "bkpgpo_default_1" {
  name                = "Plan-VM-Daily-7DR-4WR-12MR-1YR"
  resource_group_name = azurerm_resource_group.rg_prd_1.name
  recovery_vault_name = azurerm_recovery_services_vault.vault_prd_1.name
  
  #Timezone Brasilia / Brazil

  timezone = "E. South America Standard Time"

  backup {
    frequency = "Daily"
    time      = "23:00"
  }

  retention_daily {
    count = 7
  }

  retention_weekly {
    count    = 4
    weekdays = ["Sunday"]
  }

  retention_monthly {
    count    = 12
    weekdays = ["Sunday"]
    weeks    = ["Last"]
  }

  retention_yearly {
    count    = 1
    weekdays = ["Sunday"]
    weeks    = ["Last"]
    months   = ["December"]
  }
}

##########################################
###------------------------------------###
#_(SITE_1 COMMON environment - SITE_1)_###
###------------------------------------###
##########################################
#
#
#
# Create Peering HUB to SPOKE - SITE_1 COMMON
resource "azurerm_virtual_network_peering" "peering_hub1-to-spoke1" {
  name                          = "PEERING-HUB1-TO-SPOKE1"
  resource_group_name           = azurerm_resource_group.rg_prd_hub_1.name
  virtual_network_name          = azurerm_virtual_network.vnet_prd_hub_1.name
  remote_virtual_network_id     = azurerm_virtual_network.vnet_prd_1.id
  allow_virtual_network_access  = true
  allow_forwarded_traffic       = true
  allow_gateway_transit = true
  
}

# Create Peering SPOKE to HUB - SITE_1 COMMON
resource "azurerm_virtual_network_peering" "spoke1-to-hub1" {
  name                          = "PEERING-SPOKE1-TO-HUB1"
  resource_group_name           = azurerm_resource_group.rg_prd_1.name
  virtual_network_name          = azurerm_virtual_network.vnet_prd_1.name
  remote_virtual_network_id     = azurerm_virtual_network.vnet_prd_hub_1.id
  allow_virtual_network_access  = true
  allow_forwarded_traffic       = true
}


#Set Compliance Policy
resource "azurerm_policy_set_definition" "compliancepolicy" {
  name         = "nordbankPolicySet"
  policy_type  = "Custom"
  display_name = "Nordbank Policy Set"

  parameters = <<PARAMETERS
    {
        "allowedLocations": {
            "type": "Array",
            "metadata": {
                "description": "The list of allowed locations for resources.",
                "displayName": "Allowed locations",
                "strongType": "location"
            }
        }
    }
PARAMETERS

  policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/c39ba22d-4428-4149-b981-70acb31fc383"
    parameter_values     = <<VALUE
    {
      "listOfAllowedLocations": {"value": "[parameters('allowedLocations')]"}
    }
    VALUE
  }
}