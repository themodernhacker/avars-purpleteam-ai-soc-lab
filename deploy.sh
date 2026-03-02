#!/bin/bash
# Project A.V.A.R.S - Quick Start Script
# This script automates the deployment of the entire project

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="avars"
RESOURCE_GROUP="${PROJECT_NAME}-rg"
LOCATION="eastus"
ENVIRONMENT="lab"

# Functions
print_header() {
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}$1${NC}"
    echo -e "${GREEN}========================================${NC}"
}

print_info() {
    echo -e "${YELLOW}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

check_prerequisites() {
    print_header "Checking Prerequisites"
    
    # Check Azure CLI
    if ! command -v az &> /dev/null; then
        print_error "Azure CLI not installed. Install from https://aka.ms/cli"
        exit 1
    fi
    print_success "Azure CLI installed"
    
    # Check Terraform
    if ! command -v terraform &> /dev/null; then
        print_error "Terraform not installed. Install from https://www.terraform.io"
        exit 1
    fi
    print_success "Terraform installed"
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 not installed"
        exit 1
    fi
    print_success "Python 3 installed"
    
    # Check Azure login
    if ! az account show &> /dev/null; then
        print_info "Logging in to Azure..."
        az login
    else
        print_success "Already logged in to Azure"
    fi
}

prepare_variables() {
    print_header "Preparing Configuration"
    
    # Get subscription info
    SUBSCRIPTION_ID=$(az account show --query id -o tsv)
    TENANT_ID=$(az account show --query tenantId -o tsv)
    
    print_info "Subscription ID: $SUBSCRIPTION_ID"
    print_info "Tenant ID: $TENANT_ID"
    
    # Export for Terraform
    export ARM_SUBSCRIPTION_ID=$SUBSCRIPTION_ID
    export ARM_TENANT_ID=$TENANT_ID
    export ARM_SKIP_PROVIDER_REGISTRATION=true
    
    # Create terraform.tfvars if not exists
    if [ ! -f "terraform/terraform.tfvars" ]; then
        print_info "Creating terraform.tfvars..."
        cat > terraform/terraform.tfvars << EOF
azure_subscription_id = "$SUBSCRIPTION_ID"
azure_tenant_id       = "$TENANT_ID"
resource_group_name   = "$RESOURCE_GROUP"
location              = "$LOCATION"
environment           = "$ENVIRONMENT"
project_name          = "$PROJECT_NAME"

# Network
hub_vnet_cidr                = "10.0.0.0/16"
hub_firewall_subnet_cidr     = "10.0.1.0/24"
hub_management_subnet_cidr   = "10.0.2.0/24"
spoke1_vnet_cidr             = "10.1.0.0/16"
spoke1_container_subnet_cidr = "10.1.1.0/24"
spoke2_vnet_cidr             = "10.2.0.0/16"
spoke2_attack_subnet_cidr    = "10.2.1.0/24"

# Monitoring
log_analytics_retention_days = 7  # Reduced for cost

# VM
kali_vm_size = "Standard_B1s"  # Smallest SKU for cost optimization
EOF
        print_success "terraform.tfvars created"
    else
        print_info "terraform.tfvars already exists"
    fi
}

deploy_infrastructure() {
    print_header "Deploying Infrastructure (Phase 1)"
    
    cd terraform
    
    print_info "Initializing Terraform..."
    terraform init
    
    print_info "Planning deployment..."
    terraform plan -out=tfplan -input=false
    
    read -p "Review plan above. Continue? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_error "Deployment cancelled"
        exit 1
    fi
    
    print_info "Applying configuration... (this will take ~20-30 minutes)"
    terraform apply tfplan -input=false
    
    print_success "Infrastructure deployed successfully"
    
    # Save outputs
    terraform output -json > ../outputs.json
    
    cd ..
}

display_outputs() {
    print_header "Infrastructure Outputs"
    
    FIREWALL_IP=$(jq -r '.firewall_public_ip.value' outputs.json)
    JUICE_SHOP_URL=$(jq -r '.owasp_juice_shop_url.value' outputs.json)
    SSH_HONEYPOT=$(jq -r '.ssh_honeypot_url.value' outputs.json)
    KALI_IP=$(jq -r '.kali_vm_public_ip.value' outputs.json)
    
    echo ""
    echo "Critical Resources:"
    echo "===================="
    echo "Firewall Public IP:    $FIREWALL_IP"
    echo "OWASP Juice Shop:      $JUICE_SHOP_URL"
    echo "SSH Honeypot:          $SSH_HONEYPOT"
    echo "Kali Linux VM:         $KALI_IP (SSH as azureuser)"
    echo ""
    
    # Save to file for reference
    cat > resource_ips.txt << EOF
FIREWALL_IP=$FIREWALL_IP
JUICE_SHOP_URL=$JUICE_SHOP_URL
SSH_HONEYPOT=$SSH_HONEYPOT
KALI_IP=$KALI_IP
EOF
    
    print_success "IPs saved to resource_ips.txt"
}

setup_ml_environment() {
    print_header "Setting Up ML Environment (Phase 3)"
    
    print_info "Creating Python virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    
    print_info "Installing Python dependencies..."
    pip install --quiet -r ml-notebooks/requirements.txt
    
    print_success "ML environment ready"
    print_info "To activate: source venv/bin/activate"
}

quick_test() {
    print_header "Quick Connectivity Test"
    
    JUICE_SHOP_URL=$(jq -r '.owasp_juice_shop_url.value' outputs.json)
    
    print_info "Testing Juice Shop connectivity..."
    if curl -s "$JUICE_SHOP_URL" | grep -q "juice"; then
        print_success "Juice Shop is running"
    else
        print_error "Cannot reach Juice Shop - may still be starting"
    fi
}

print_next_steps() {
    print_header "Project A.V.A.R.S - Deployment Complete!"
    
    echo ""
    echo "Next Steps:"
    echo "==========="
    echo ""
    echo "1. PHASE 2 - Run Attacks:"
    echo "   cd Project\\ A.V.A.R.S"
    echo "   python scripts/attacks/credential_stuffing.py <JUICE_SHOP_URL>"
    echo "   python scripts/attacks/sql_injection.py <JUICE_SHOP_URL>"
    echo ""
    echo "2. PHASE 3 - Train ML Models:"
    echo "   source venv/bin/activate"
    echo "   jupyter notebook ml-notebooks/anomaly_detection.ipynb"
    echo ""
    echo "3. PHASE 4 - Configure Azure Logic Apps:"
    echo "   - Import logic-apps/incident_response_workflow.json"
    echo "   - Connect to Microsoft Sentinel"
    echo "   - Configure Azure OpenAI connection"
    echo ""
    echo "4. Monitor in Microsoft Sentinel:"
    echo "   - Logs > Run KQL queries from scripts/kql/"
    echo "   - Watch for alerts in real-time"
    echo ""
    echo "Documentation:"
    echo "  - Architecture: docs/ARCHITECTURE.md"
    echo "  - Deployment: docs/DEPLOYMENT.md"
    echo "  - README: README.md"
    echo ""
    echo "Email alerts file created: resource_ips.txt"
    echo ""
}

# Main execution
main() {
    print_header "Project A.V.A.R.S - Deployment Script"
    
    check_prerequisites
    prepare_variables
    deploy_infrastructure
    display_outputs
    setup_ml_environment
    quick_test
    print_next_steps
    
    print_success "Deployment completed successfully!"
}

# Run main function
main
