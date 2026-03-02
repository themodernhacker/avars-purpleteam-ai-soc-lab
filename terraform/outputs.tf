# Terraform Outputs

output "resource_group_name" {
  description = "Name of the resource group"
  value       = azurerm_resource_group.avars.name
}

output "resource_group_id" {
  description = "ID of the resource group"
  value       = azurerm_resource_group.avars.id
}

# ============================================================
# Network Outputs
# ============================================================

output "hub_vnet_id" {
  description = "ID of Hub Virtual Network"
  value       = azurerm_virtual_network.hub.id
}

output "hub_vnet_name" {
  description = "Name of Hub Virtual Network"
  value       = azurerm_virtual_network.hub.name
}

output "spoke1_vnet_id" {
  description = "ID of Spoke 1 (Honey-Net) Virtual Network"
  value       = azurerm_virtual_network.spoke1_honeynet.id
}

output "spoke1_vnet_name" {
  description = "Name of Spoke 1 Virtual Network"
  value       = azurerm_virtual_network.spoke1_honeynet.name
}

output "spoke2_vnet_id" {
  description = "ID of Spoke 2 (Management) Virtual Network"
  value       = azurerm_virtual_network.spoke2_management.id
}

output "spoke2_vnet_name" {
  description = "Name of Spoke 2 Virtual Network"
  value       = azurerm_virtual_network.spoke2_management.name
}

# ============================================================
# Firewall Outputs
# ============================================================

output "firewall_id" {
  description = "ID of Azure Firewall"
  value       = azurerm_firewall.avars.id
}

output "firewall_name" {
  description = "Name of Azure Firewall"
  value       = azurerm_firewall.avars.name
}

output "firewall_private_ip" {
  description = "Private IP Address of Azure Firewall"
  value       = azurerm_firewall.avars.ip_configuration[0].private_ip_address
}

output "firewall_public_ip" {
  description = "Public IP Address of Azure Firewall"
  value       = azurerm_public_ip.firewall.ip_address
}

# ============================================================
# Honeypot Outputs
# ============================================================

output "owasp_juice_shop_url" {
  description = "URL to access OWASP Juice Shop"
  value       = "http://${azurerm_container_group.juice_shop.fqdn}:${var.honeypot_port_http}"
  sensitive   = false
}

output "owasp_juice_shop_fqdn" {
  description = "FQDN of OWASP Juice Shop"
  value       = azurerm_container_group.juice_shop.fqdn
}

output "ssh_honeypot_fqdn" {
  description = "FQDN of SSH Honeypot"
  value       = azurerm_container_group.ssh_honeypot.fqdn
}

output "ssh_honeypot_url" {
  description = "SSH connection string for honeypot"
  value       = "ssh root@${azurerm_container_group.ssh_honeypot.fqdn}"
}

# ============================================================
# Kali Linux Attack VM Outputs
# ============================================================

output "kali_vm_id" {
  description = "ID of Kali Linux VM"
  value       = azurerm_linux_virtual_machine.kali.id
}

output "kali_vm_name" {
  description = "Name of Kali Linux VM"
  value       = azurerm_linux_virtual_machine.kali.name
}

output "kali_vm_private_ip" {
  description = "Private IP address of Kali VM"
  value       = azurerm_network_interface.kali_nic.private_ip_address
}

output "kali_vm_public_ip" {
  description = "Public IP address of Kali VM"
  value       = azurerm_public_ip.kali.ip_address
}

output "kali_ssh_command" {
  description = "SSH connection command for Kali VM"
  value       = "ssh ${var.kali_admin_username}@${azurerm_public_ip.kali.ip_address}"
  sensitive   = true
}

output "kali_admin_username" {
  description = "Admin username for Kali VM"
  value       = var.kali_admin_username
  sensitive   = true
}

# Password stored in Key Vault - reference it there
output "kali_password_keyvault_secret" {
  description = "Key Vault secret containing Kali password"
  value       = "kali-vm-password"
}

# ============================================================
# Monitoring Outputs
# ============================================================

output "log_analytics_workspace_id" {
  description = "ID of Log Analytics Workspace"
  value       = azurerm_log_analytics_workspace.avars.id
}

output "log_analytics_workspace_name" {
  description = "Name of Log Analytics Workspace"
  value       = azurerm_log_analytics_workspace.avars.name
}

output "log_analytics_workspace_resource_id" {
  description = "Resource ID of Log Analytics Workspace"
  value       = azurerm_log_analytics_workspace.avars.workspace_id
}

output "log_analytics_customer_id" {
  description = "Customer ID for Log Analytics (for AMA configuration)"
  value       = azurerm_log_analytics_workspace.avars.workspace_id
}

# ============================================================
# Key Vault Outputs
# ============================================================

output "key_vault_id" {
  description = "ID of Key Vault"
  value       = azurerm_key_vault.avars.id
}

output "key_vault_name" {
  description = "Name of Key Vault"
  value       = azurerm_key_vault.avars.name
}

output "key_vault_uri" {
  description = "URI of Key Vault"
  value       = azurerm_key_vault.avars.vault_uri
}

# ============================================================
# Deployment Summary
# ============================================================

output "deployment_summary" {
  description = "Summary of deployed infrastructure"
  value = {
    hub_network         = azurerm_virtual_network.hub.name
    firewall_public_ip  = azurerm_public_ip.firewall.ip_address
    honeypot_web_url    = "http://${azurerm_container_group.juice_shop.fqdn}:${var.honeypot_port_http}"
    honeypot_ssh_host   = azurerm_container_group.ssh_honeypot.fqdn
    attack_vm_public_ip = azurerm_public_ip.kali.ip_address
    siem_workspace      = azurerm_log_analytics_workspace.avars.name
    sentinel_enabled    = var.sentinel_enabled
  }
}
