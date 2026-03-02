# Project A.V.A.R.S - Quick Start Guide (Windows PowerShell)
# Run this script in PowerShell as Administrator

$ErrorActionPreference = "Stop"

# Colors
$GREEN = "Green"
$YELLOW = "Yellow"
$RED = "Red"

function Write-Header {
    param([string]$Message)
    Write-Host "========================================" -ForegroundColor $GREEN
    Write-Host $Message -ForegroundColor $GREEN
    Write-Host "========================================" -ForegroundColor $GREEN
    Write-Host ""
}

function Write-Info {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor $YELLOW
}

function Write-Success {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor $GREEN
}

function Write-Error {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor $RED
}

function Check-Prerequisites {
    Write-Header "Checking Prerequisites"
    
    # Check Azure CLI
    try {
        $azVersion = az --version 2>$null | Select-Object -First 1
        Write-Success "Azure CLI installed"
    }
    catch {
        Write-Error "Azure CLI not found. Install from: https://aka.ms/cli"
        exit 1
    }
    
    # Check Terraform
    try {
        $tfVersion = terraform -version 2>$null
        Write-Success "Terraform installed"
    }
    catch {
        Write-Error "Terraform not found. Install from: https://www.terraform.io"
        exit 1
    }
    
    # Check Python
    try {
        $pyVersion = python --version
        Write-Success "Python installed: $pyVersion"
    }
    catch {
        Write-Error "Python not found. Install from: https://www.python.org"
        exit 1
    }
    
    # Check Azure Login
    try {
        $account = az account show 2>$null
        Write-Success "Already logged into Azure"
    }
    catch {
        Write-Info "Logging into Azure..."
        az login
        Write-Success "Azure login successful"
    }
}

function Prepare-Configuration {
    Write-Header "Preparing Configuration"
    
    # Get Azure subscription info
    $subscription = az account show | ConvertFrom-Json
    $subscriptionId = $subscription.id
    $tenantId = $subscription.tenantId
    
    Write-Info "Subscription ID: $subscriptionId"
    Write-Info "Tenant ID: $tenantId"
    
    # Set environment variables
    $env:ARM_SUBSCRIPTION_ID = $subscriptionId
    $env:ARM_TENANT_ID = $tenantId
    $env:ARM_SKIP_PROVIDER_REGISTRATION = "true"
    
    # Create terraform.tfvars if not exists
    $tfvarsPath = "terraform\terraform.tfvars"
    if (-not (Test-Path $tfvarsPath)) {
        Write-Info "Creating terraform.tfvars..."
        
        $tfvarsContent = @"
azure_subscription_id = "$subscriptionId"
azure_tenant_id       = "$tenantId"
resource_group_name   = "avars-rg"
location              = "eastus"
environment           = "lab"
project_name          = "avars"

hub_vnet_cidr                = "10.0.0.0/16"
hub_firewall_subnet_cidr     = "10.0.1.0/24"
hub_management_subnet_cidr   = "10.0.2.0/24"
spoke1_vnet_cidr             = "10.1.0.0/16"
spoke1_container_subnet_cidr = "10.1.1.0/24"
spoke2_vnet_cidr             = "10.2.0.0/16"
spoke2_attack_subnet_cidr    = "10.2.1.0/24"

log_analytics_retention_days = 7
kali_vm_size = "Standard_B1s"
"@
        
        Set-Content -Path $tfvarsPath -Value $tfvarsContent
        Write-Success "terraform.tfvars created"
    }
    else {
        Write-Info "terraform.tfvars already exists"
    }
}

function Deploy-Infrastructure {
    Write-Header "Deploying Infrastructure (Phase 1)"
    
    Push-Location terraform
    
    Write-Info "Initializing Terraform..."
    terraform init
    
    Write-Info "Planning deployment..."
    terraform plan -out=tfplan -input=false
    
    Write-Host "Review the plan above."
    $continue = Read-Host "Deploy infrastructure? (y/n)"
    
    if ($continue -ne 'y') {
        Write-Error "Deployment cancelled"
        exit 1
    }
    
    Write-Info "Applying configuration (this takes 20-30 minutes)..."
    terraform apply tfplan -input=false
    
    Write-Success "Infrastructure deployed"
    
    # Save outputs
    terraform output -json | Out-File -FilePath ..\outputs.json
    
    Pop-Location
}

function Display-Outputs {
    Write-Header "Infrastructure Resources"
    
    $outputs = Get-Content -Path outputs.json | ConvertFrom-Json
    
    Write-Host "Firewall IP:       " -NoNewline
    Write-Host ($outputs.firewall_public_ip.value) -ForegroundColor Green
    
    Write-Host "Juice Shop URL:    " -NoNewline
    Write-Host ($outputs.owasp_juice_shop_url.value) -ForegroundColor Green
    
    Write-Host "SSH Honeypot:      " -NoNewline
    Write-Host ($outputs.ssh_honeypot_url.value) -ForegroundColor Green
    
    Write-Host "Kali Linux IP:     " -NoNewline
    Write-Host ($outputs.kali_vm_public_ip.value) -ForegroundColor Green
    
    Write-Host ""
    Write-Success "Save these IPs - you will need them for attacks!"
}

function Setup-ML-Environment {
    Write-Header "Setting Up ML Environment"
    
    Write-Info "Creating Python virtual environment..."
    python -m venv venv
    
    Write-Info "Activating virtual environment..."
    & ".\venv\Scripts\Activate.ps1"
    
    Write-Info "Installing dependencies..."
    pip install --quiet -r ml-notebooks\requirements.txt
    
    Write-Success "ML environment ready"
}

function Show-NextSteps {
    Write-Header "Project A.V.A.R.S - Deployment Complete!"
    
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Green
    Write-Host "============" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "1. Run Attack Simulations (Phase 2):"
    Write-Host "   python scripts\attacks\credential_stuffing.py <JUICE_SHOP_URL>"
    Write-Host "   python scripts\attacks\sql_injection.py <JUICE_SHOP_URL>"
    Write-Host ""
    
    Write-Host "2. Train ML Models (Phase 3):"
    Write-Host "   .\venv\Scripts\activate"
    Write-Host "   jupyter notebook ml-notebooks\anomaly_detection.ipynb"
    Write-Host ""
    
    Write-Host "3. Configure Sentinel (Phase 4):"
    Write-Host "   - Import KQL queries from scripts/kql/"
    Write-Host "   - Create alert rules"
    Write-Host "   - Link to Logic Apps"
    Write-Host ""
    
    Write-Host "Documentation:"
    Write-Host "   - README.md"
    Write-Host "   - docs\DEPLOYMENT.md"
    Write-Host "   - docs\ARCHITECTURE.md"
    Write-Host ""
}

# Main Execution
Write-Header "Project A.V.A.R.S - Windows Deployment"

Check-Prerequisites
Prepare-Configuration
Deploy-Infrastructure
Display-Outputs
Setup-ML-Environment
Show-NextSteps

Write-Success "Deployment completed! Ready to proceed with Phase 2."
