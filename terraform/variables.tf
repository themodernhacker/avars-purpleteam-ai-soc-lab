# Terraform Variables for Project A.V.A.R.S

variable "azure_subscription_id" {
  description = "Azure Subscription ID"
  type        = string
}

variable "azure_tenant_id" {
  description = "Azure Tenant ID"
  type        = string
}

variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
  default     = "avars-rg"
}

variable "location" {
  description = "Azure region for resources"
  type        = string
  default     = "eastus"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "lab"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "avars"
}

# Network Variables
variable "hub_vnet_cidr" {
  description = "CIDR block for Hub VNet"
  type        = string
  default     = "10.0.0.0/16"
}

variable "hub_firewall_subnet_cidr" {
  description = "CIDR block for Firewall subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "hub_management_subnet_cidr" {
  description = "CIDR block for management subnet"
  type        = string
  default     = "10.0.2.0/24"
}

variable "spoke1_vnet_cidr" {
  description = "CIDR block for Spoke 1 (Honey-Net)"
  type        = string
  default     = "10.1.0.0/16"
}

variable "spoke1_container_subnet_cidr" {
  description = "CIDR block for container subnet"
  type        = string
  default     = "10.1.1.0/24"
}

variable "spoke2_vnet_cidr" {
  description = "CIDR block for Spoke 2 (Management)"
  type        = string
  default     = "10.2.0.0/16"
}

variable "spoke2_attack_subnet_cidr" {
  description = "CIDR block for attack VM subnet"
  type        = string
  default     = "10.2.1.0/24"
}

# Monitoring Variables
variable "log_analytics_retention_days" {
  description = "Log Analytics workspace retention in days"
  type        = number
  default     = 30
}

variable "sentinel_enabled" {
  description = "Enable Microsoft Sentinel"
  type        = bool
  default     = true
}

variable "deploy_sentinel_rules" {
  description = "Deploy Sentinel scheduled analytics rules during initial apply"
  type        = bool
  default     = false
}

variable "deploy_metric_alerts" {
  description = "Deploy Azure Monitor metric alerts during initial apply"
  type        = bool
  default     = false
}

variable "deploy_resourcegroup_diagnostics" {
  description = "Deploy diagnostic settings on resource group"
  type        = bool
  default     = false
}

variable "deploy_aks" {
  description = "Deploy AKS cluster and container registry"
  type        = bool
  default     = false
}

variable "enable_defender_cloud" {
  description = "Enable Defender for Cloud plans"
  type        = bool
  default     = true
}

# Honeypot Variables
variable "juice_shop_image" {
  description = "Docker image URI for OWASP Juice Shop"
  type        = string
  default     = "bkimminich/juice-shop:latest"
}

variable "honeypot_port_http" {
  description = "HTTP port for honeypot"
  type        = number
  default     = 80
}

variable "honeypot_port_https" {
  description = "HTTPS port for honeypot"
  type        = number
  default     = 443
}

variable "honeypot_port_ssh" {
  description = "SSH port for honeypot"
  type        = number
  default     = 22
}

# Firewall Variables
variable "firewall_sku" {
  description = "SKU for Azure Firewall"
  type        = string
  default     = "Standard"
}

variable "allow_kali_ip" {
  description = "Allow Kali Linux VM public IP (for attack execution)"
  type        = bool
  default     = true
}

# Kali Linux Variables
variable "kali_vm_size" {
  description = "VM size for Kali Linux"
  type        = string
  default     = "Standard_B1s"
}

variable "kali_admin_username" {
  description = "Admin username for Kali VM"
  type        = string
  default     = "azureuser"
  sensitive   = true
}

variable "deploy_kali_monitoring_extensions" {
  description = "Deploy Azure Monitor/Dependency extensions on Kali VM"
  type        = bool
  default     = false
}

# Tags
variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default = {
    Project     = "A.V.A.R.S"
    Environment = "Lab"
    ManagedBy   = "Terraform"
    Purpose     = "Cybersecurity Lab"
  }
}
