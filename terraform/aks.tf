# ==============================================================================
# AKS Platform Module (Provider-Compatible Refactor)
# ==============================================================================

variable "aks_node_count" {
  description = "Default AKS node count"
  type        = number
  default     = 2
}

variable "aks_node_vm_size" {
  description = "AKS node VM size"
  type        = string
  default     = "Standard_B2s"
}

variable "aks_ssh_public_key" {
  description = "SSH public key for AKS Linux profile"
  type        = string
  default     = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCu7m5hH5kq1n7lH9Qk9m3r3z7x9M2vQ8g3j9k0x7m4r2n6v8d1q3s5w7y9z0a2b4c6d8e0f2g4h6j8k0l2m4n6p8q0r2s4t6u8v0w2x4y6z8a0b2c4d6e8f0g2h4j6k8l0m2n4p6q8r0s2t4u6v8w0x2y4z6 test@avars"
}

resource "random_string" "aks_suffix" {
  count   = var.deploy_aks ? 1 : 0
  length  = 5
  special = false
  upper   = false
}

resource "azurerm_container_registry" "avars_acr" {
  count               = var.deploy_aks ? 1 : 0
  name                = "acr${replace(local.resource_prefix, "-", "")}${random_string.aks_suffix[0].result}"
  resource_group_name = azurerm_resource_group.avars.name
  location            = azurerm_resource_group.avars.location
  sku                 = "Basic"
  admin_enabled       = false

  tags = merge(local.common_tags, {
    Module = "aks"
    Scope  = "container-registry"
  })
}

resource "azurerm_kubernetes_cluster" "avars_aks" {
  count               = var.deploy_aks ? 1 : 0
  name                = "${local.resource_prefix}-aks"
  location            = azurerm_resource_group.avars.location
  resource_group_name = azurerm_resource_group.avars.name
  dns_prefix          = "${replace(local.resource_prefix, "-", "")}-aks"

  default_node_pool {
    name           = "system"
    node_count     = var.aks_node_count
    vm_size        = var.aks_node_vm_size
    vnet_subnet_id = azurerm_subnet.spoke2_attack.id
  }

  identity {
    type = "SystemAssigned"
  }

  linux_profile {
    admin_username = "aksadmin"

    ssh_key {
      key_data = var.aks_ssh_public_key
    }
  }

  network_profile {
    network_plugin    = "azure"
    load_balancer_sku = "standard"
    network_policy    = "azure"
  }

  role_based_access_control_enabled = true

  tags = merge(local.common_tags, {
    Module = "aks"
    Scope  = "cluster"
  })

  depends_on = [
    azurerm_subnet.spoke2_attack,
    azurerm_container_registry.avars_acr
  ]
}

output "aks_cluster_name_refactored" {
  description = "AKS cluster name"
  value       = var.deploy_aks ? azurerm_kubernetes_cluster.avars_aks[0].name : null
}
