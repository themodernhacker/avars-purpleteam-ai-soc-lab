# Honeypot and Attack Infrastructure

resource "random_string" "honeypot_dns_suffix" {
  length  = 5
  lower   = true
  upper   = false
  numeric = true
  special = false
}

# ============================================================
# 1. OWASP JUICE SHOP CONTAINER (Spoke 1)
# ============================================================

# Create network interface for container
resource "azurerm_network_interface" "juice_shop_nic" {
  count               = 0
  name                = "${local.resource_prefix}-juice-shop-nic"
  location            = azurerm_resource_group.avars.location
  resource_group_name = azurerm_resource_group.avars.name

  ip_configuration {
    name                          = "testconfiguration1"
    subnet_id                     = azurerm_subnet.spoke1_container.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.juice_shop.id
  }

  tags = merge(
    local.common_tags,
    { Purpose = "OWASP Juice Shop Web Honeypot" }
  )
}

# Public IP for Juice Shop
resource "azurerm_public_ip" "juice_shop" {
  name                = "${local.resource_prefix}-juice-shop-pip"
  location            = azurerm_resource_group.avars.location
  resource_group_name = azurerm_resource_group.avars.name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = merge(
    local.common_tags,
    { Purpose = "OWASP Juice Shop Public Access" }
  )
}

# Network Interface for Container Instance
resource "azurerm_network_interface" "honeypot_container" {
  count               = 0
  name                = "${local.resource_prefix}-honeypot-nic"
  location            = azurerm_resource_group.avars.location
  resource_group_name = azurerm_resource_group.avars.name

  ip_configuration {
    name                          = "testconfiguration1"
    subnet_id                     = azurerm_subnet.spoke1_container.id
    private_ip_address_allocation = "Dynamic"
  }

  tags = merge(
    local.common_tags,
    { Purpose = "Honeypot Container Interface" }
  )
}

# ============================================================
# 2. SSH HONEYPOT (Cowrie - Linux)
# ============================================================

# Create Azure Container Instance for SSH Honeypot
resource "azurerm_container_group" "ssh_honeypot" {
  name                = "${local.resource_prefix}-ssh-honeypot"
  location            = azurerm_resource_group.avars.location
  resource_group_name = azurerm_resource_group.avars.name
  os_type             = "Linux"
  ip_address_type     = "Public"
  dns_name_label      = "${local.resource_prefix}-ssh-honeypot-${random_string.honeypot_dns_suffix.result}"

  container {
    name   = "cowrie"
    image  = "cowrie/cowrie:latest"
    cpu    = "0.5"
    memory = "1.0"

    ports {
      port     = var.honeypot_port_ssh
      protocol = "TCP"
    }

    environment_variables = {
      COWRIE_HOSTNAME  = "secure-server"
      COWRIE_LOG_LEVEL = "info"
    }
  }

  tags = merge(
    local.common_tags,
    { Purpose = "SSH Honeypot (Cowrie)" }
  )
}

# ============================================================
# 3. OWASP JUICE SHOP CONTAINER
# ============================================================

resource "azurerm_container_group" "juice_shop" {
  name                = "${local.resource_prefix}-owasp-juice-shop"
  location            = azurerm_resource_group.avars.location
  resource_group_name = azurerm_resource_group.avars.name
  os_type             = "Linux"
  ip_address_type     = "Public"
  dns_name_label      = "${local.resource_prefix}-juice-shop-${random_string.honeypot_dns_suffix.result}"

  container {
    name   = "juice-shop"
    image  = var.juice_shop_image
    cpu    = "1.0"
    memory = "2.0"

    ports {
      port     = var.honeypot_port_http
      protocol = "TCP"
    }

    environment_variables = {
      PORT = tostring(var.honeypot_port_http)
    }
  }

  tags = merge(
    local.common_tags,
    { Purpose = "OWASP Juice Shop Web Honeypot" }
  )
}

# ============================================================
# 4. KALI LINUX ATTACK VM (Spoke 2)
# ============================================================

# Generate random suffix for VM name uniqueness
resource "random_string" "kali_suffix" {
  length  = 4
  special = false
}

# Network Interface for Kali VM
resource "azurerm_network_interface" "kali_nic" {
  name                = "${local.resource_prefix}-kali-nic"
  location            = azurerm_resource_group.avars.location
  resource_group_name = azurerm_resource_group.avars.name

  ip_configuration {
    name                          = "testconfiguration1"
    subnet_id                     = azurerm_subnet.spoke2_attack.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.kali.id
  }

  tags = merge(
    local.common_tags,
    { Purpose = "Kali Linux Attack VM" }
  )
}

# Public IP for Kali VM
resource "azurerm_public_ip" "kali" {
  name                = "${local.resource_prefix}-kali-pip"
  location            = azurerm_resource_group.avars.location
  resource_group_name = azurerm_resource_group.avars.name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = merge(
    local.common_tags,
    { Purpose = "Kali Linux Public SSH Access" }
  )
}

# Kali Linux Virtual Machine
resource "azurerm_linux_virtual_machine" "kali" {
  name                = "${local.resource_prefix}-kali-${random_string.kali_suffix.result}"
  location            = azurerm_resource_group.avars.location
  resource_group_name = azurerm_resource_group.avars.name
  size                = var.kali_vm_size

  disable_password_authentication = false
  admin_username                  = var.kali_admin_username

  # Generate secure random password
  admin_password = random_password.kali_password.result

  network_interface_ids = [
    azurerm_network_interface.kali_nic.id,
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }

  # Use a broadly available Ubuntu image for student subscriptions/regions
  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  # Install Azure Monitor Agent automatically
  identity {
    type = "SystemAssigned"
  }

  tags = merge(
    local.common_tags,
    { Purpose = "Offensive Security - Kali Linux Attack VM" }
  )
}

# Random password for Kali VM
resource "random_password" "kali_password" {
  length           = 20
  override_special = "!@#$%^&*()_+-=[]{}|:;"
  min_upper        = 2
  min_lower        = 2
  min_numeric      = 2
  min_special      = 2
}

# Store Kali password in Key Vault
resource "azurerm_key_vault_secret" "kali_password" {
  name         = "kali-vm-password"
  value        = random_password.kali_password.result
  key_vault_id = azurerm_key_vault.avars.id

  tags = local.common_tags

  depends_on = [
    azurerm_key_vault_access_policy.terraform_current_identity_policy,
    azurerm_key_vault_access_policy.automation_identity_policy,
  ]
}

# ============================================================
# 5. AZURE MONITOR AGENT (For Log Collection)
# ============================================================

# VM Extension for Azure Monitor Agent on Kali
resource "azurerm_virtual_machine_extension" "ama_kali" {
  count                = var.deploy_kali_monitoring_extensions ? 1 : 0
  name                 = "AMA-${azurerm_linux_virtual_machine.kali.name}"
  virtual_machine_id   = azurerm_linux_virtual_machine.kali.id
  publisher            = "Microsoft.Azure.Monitor"
  type                 = "AzureMonitorLinuxAgent"
  type_handler_version = "1.0"

  depends_on = [azurerm_linux_virtual_machine.kali]
}

# ============================================================
# 6. VM INSIGHTS (Performance Monitoring)
# ============================================================

# VM Insights Extension for Kali
resource "azurerm_virtual_machine_extension" "vm_insights_kali" {
  count                      = var.deploy_kali_monitoring_extensions ? 1 : 0
  name                       = "DependencyAgent-${azurerm_linux_virtual_machine.kali.name}"
  virtual_machine_id         = azurerm_linux_virtual_machine.kali.id
  publisher                  = "Microsoft.Azure.Monitoring.DependencyAgent"
  type                       = "DependencyAgentLinux"
  type_handler_version       = "9.10"
  auto_upgrade_minor_version = true

  settings = jsonencode({
    enableAMA = true
  })

  tags = local.common_tags

  depends_on = [azurerm_virtual_machine_extension.ama_kali]
}
