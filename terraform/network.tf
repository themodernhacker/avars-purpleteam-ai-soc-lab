# Network Infrastructure - Hub and Spoke Architecture

# ============================================================
# 1. HUB VIRTUAL NETWORK
# ============================================================
resource "azurerm_virtual_network" "hub" {
  name                = local.hub_vnet_name
  address_space       = [var.hub_vnet_cidr]
  location            = azurerm_resource_group.avars.location
  resource_group_name = azurerm_resource_group.avars.name

  tags = local.common_tags
}

# Hub Firewall Subnet
resource "azurerm_subnet" "hub_firewall" {
  name                 = "AzureFirewallSubnet" # Required name for Azure Firewall
  resource_group_name  = azurerm_resource_group.avars.name
  virtual_network_name = azurerm_virtual_network.hub.name
  address_prefixes     = [var.hub_firewall_subnet_cidr]
}

# Hub Management Subnet
resource "azurerm_subnet" "hub_management" {
  name                 = "${var.project_name}-hub-mgmt-subnet"
  resource_group_name  = azurerm_resource_group.avars.name
  virtual_network_name = azurerm_virtual_network.hub.name
  address_prefixes     = [var.hub_management_subnet_cidr]
}

# ============================================================
# 2. SPOKE 1 VIRTUAL NETWORK (Honey-Net)
# ============================================================
resource "azurerm_virtual_network" "spoke1_honeynet" {
  name                = local.spoke1_vnet_name
  address_space       = [var.spoke1_vnet_cidr]
  location            = azurerm_resource_group.avars.location
  resource_group_name = azurerm_resource_group.avars.name

  tags = merge(
    local.common_tags,
    { Purpose = "Honeypot Network" }
  )
}

# Spoke 1 Container Subnet
resource "azurerm_subnet" "spoke1_container" {
  name                 = "${var.project_name}-spoke1-aci-subnet"
  resource_group_name  = azurerm_resource_group.avars.name
  virtual_network_name = azurerm_virtual_network.spoke1_honeynet.name
  address_prefixes     = [var.spoke1_container_subnet_cidr]

  # Allow container instances to be deployed
  delegation {
    name = "aciDelegation"
    service_delegation {
      name    = "Microsoft.ContainerInstance/containerGroups"
      actions = ["Microsoft.Network/virtualNetworks/subnets/action"]
    }
  }
}

# ============================================================
# 3. SPOKE 2 VIRTUAL NETWORK (Management/Attack)
# ============================================================
resource "azurerm_virtual_network" "spoke2_management" {
  name                = local.spoke2_vnet_name
  address_space       = [var.spoke2_vnet_cidr]
  location            = azurerm_resource_group.avars.location
  resource_group_name = azurerm_resource_group.avars.name

  tags = merge(
    local.common_tags,
    { Purpose = "Management and Attack Network" }
  )
}

# Spoke 2 Attack VM Subnet
resource "azurerm_subnet" "spoke2_attack" {
  name                 = "${var.project_name}-spoke2-attack-subnet"
  resource_group_name  = azurerm_resource_group.avars.name
  virtual_network_name = azurerm_virtual_network.spoke2_management.name
  address_prefixes     = [var.spoke2_attack_subnet_cidr]
}

# ============================================================
# 4. VNET PEERING
# ============================================================

# Hub to Spoke 1 Peering
resource "azurerm_virtual_network_peering" "hub_to_spoke1" {
  name                         = "${local.hub_vnet_name}-to-${local.spoke1_vnet_name}"
  resource_group_name          = azurerm_resource_group.avars.name
  virtual_network_name         = azurerm_virtual_network.hub.name
  remote_virtual_network_id    = azurerm_virtual_network.spoke1_honeynet.id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
  allow_gateway_transit        = false
  use_remote_gateways          = false
}

# Spoke 1 to Hub Peering
resource "azurerm_virtual_network_peering" "spoke1_to_hub" {
  name                         = "${local.spoke1_vnet_name}-to-${local.hub_vnet_name}"
  resource_group_name          = azurerm_resource_group.avars.name
  virtual_network_name         = azurerm_virtual_network.spoke1_honeynet.name
  remote_virtual_network_id    = azurerm_virtual_network.hub.id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
  allow_gateway_transit        = false
  use_remote_gateways          = false
}

# Hub to Spoke 2 Peering
resource "azurerm_virtual_network_peering" "hub_to_spoke2" {
  name                         = "${local.hub_vnet_name}-to-${local.spoke2_vnet_name}"
  resource_group_name          = azurerm_resource_group.avars.name
  virtual_network_name         = azurerm_virtual_network.hub.name
  remote_virtual_network_id    = azurerm_virtual_network.spoke2_management.id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
  allow_gateway_transit        = false
  use_remote_gateways          = false
}

# Spoke 2 to Hub Peering
resource "azurerm_virtual_network_peering" "spoke2_to_hub" {
  name                         = "${local.spoke2_vnet_name}-to-${local.hub_vnet_name}"
  resource_group_name          = azurerm_resource_group.avars.name
  virtual_network_name         = azurerm_virtual_network.spoke2_management.name
  remote_virtual_network_id    = azurerm_virtual_network.hub.id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
  allow_gateway_transit        = false
  use_remote_gateways          = false
}

# ============================================================
# 5. NETWORK SECURITY GROUPS
# ============================================================

# Hub NSG
resource "azurerm_network_security_group" "hub" {
  name                = "${local.resource_prefix}-hub-nsg"
  location            = azurerm_resource_group.avars.location
  resource_group_name = azurerm_resource_group.avars.name

  security_rule {
    name                       = "AllowAzureServices"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "AzureCloud"
    destination_address_prefix = "*"
  }

  tags = local.common_tags
}

resource "azurerm_subnet_network_security_group_association" "hub_management" {
  subnet_id                 = azurerm_subnet.hub_management.id
  network_security_group_id = azurerm_network_security_group.hub.id
}

# Spoke 1 Honey-Net NSG (Intentionally permissive for attack surface)
resource "azurerm_network_security_group" "spoke1_honeynet" {
  name                = "${local.resource_prefix}-spoke1-honeynet-nsg"
  location            = azurerm_resource_group.avars.location
  resource_group_name = azurerm_resource_group.avars.name

  security_rule {
    name                       = "AllowHTTP"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = tostring(var.honeypot_port_http)
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowHTTPS"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = tostring(var.honeypot_port_https)
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowSSH"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = tostring(var.honeypot_port_ssh)
    source_address_prefix      = var.allow_kali_ip ? "*" : "VirtualNetwork"
    destination_address_prefix = "*"
  }

  # Honeypot typically allows all traffic for attack simulation
  security_rule {
    name                       = "AllowAllInbound"
    priority                   = 130
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = merge(
    local.common_tags,
    { Warning = "Intentionally Permissive - Honeypot Network" }
  )
}

resource "azurerm_subnet_network_security_group_association" "spoke1_container" {
  subnet_id                 = azurerm_subnet.spoke1_container.id
  network_security_group_id = azurerm_network_security_group.spoke1_honeynet.id
}

# Spoke 2 Attack NSG
resource "azurerm_network_security_group" "spoke2_attack" {
  name                = "${local.resource_prefix}-spoke2-attack-nsg"
  location            = azurerm_resource_group.avars.location
  resource_group_name = azurerm_resource_group.avars.name

  security_rule {
    name                       = "AllowSSH"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowRDP"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = var.allow_kali_ip ? "*" : "VirtualNetwork"
    destination_address_prefix = "*"
  }

  tags = local.common_tags
}

resource "azurerm_subnet_network_security_group_association" "spoke2_attack" {
  subnet_id                 = azurerm_subnet.spoke2_attack.id
  network_security_group_id = azurerm_network_security_group.spoke2_attack.id
}

# ============================================================
# 6. AZURE FIREWALL
# ============================================================

# Public IP for Firewall
resource "azurerm_public_ip" "firewall" {
  name                = "${local.resource_prefix}-fw-pip"
  location            = azurerm_resource_group.avars.location
  resource_group_name = azurerm_resource_group.avars.name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = local.common_tags
}

# Azure Firewall Policy
resource "azurerm_firewall_policy" "avars" {
  name                = "${local.resource_prefix}-fw-policy"
  location            = azurerm_resource_group.avars.location
  resource_group_name = azurerm_resource_group.avars.name

  insights {
    enabled                            = true
    default_log_analytics_workspace_id = azurerm_log_analytics_workspace.avars.id
    retention_in_days                  = 30
  }

  tags = local.common_tags
}

# Azure Firewall
resource "azurerm_firewall" "avars" {
  name                = local.firewall_name
  location            = azurerm_resource_group.avars.location
  resource_group_name = azurerm_resource_group.avars.name
  sku_tier            = var.firewall_sku
  sku_name            = "AZFW_VNet"
  firewall_policy_id  = azurerm_firewall_policy.avars.id

  ip_configuration {
    name                 = "configuration"
    subnet_id            = azurerm_subnet.hub_firewall.id
    public_ip_address_id = azurerm_public_ip.firewall.id
  }

  tags = local.common_tags
}

# Firewall Diagnostic Settings
resource "azurerm_monitor_diagnostic_setting" "firewall" {
  name                       = "${local.firewall_name}-diag"
  target_resource_id         = azurerm_firewall.avars.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.avars.id

  enabled_log {
    category = "AzureFirewallApplicationRule"
  }

  enabled_log {
    category = "AzureFirewallNetworkRule"
  }

  enabled_log {
    category = "AzureFirewallDnsProxy"
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}
