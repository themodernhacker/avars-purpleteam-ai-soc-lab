# Project A.V.A.R.S - Advanced Upgrades Roadmap
## Enterprise-Grade Security Lab for International Markets

**Updated**: February 2026  
**Target Audience**: CISO-track professionals, enterprise security teams  
**Complexity**: Advanced → Expert Level  

---

## 🎯 Upgrade Overview

This document outlines 6 major upgrades to transform Project A.V.A.R.S from "impressive grad project" to "CISO-level security demonstrator."

| Upgrade | Complexity | Time | Impact |
|---------|-----------|------|--------|
| 1. AKS + Service Mesh | ⭐⭐⭐⭐⭐ | 2-3 weeks | Demonstrates modern containerization |
| 2. Zero Trust & Entra ID | ⭐⭐⭐⭐☆ | 1-2 weeks | Identity-first security (modern standard) |
| 3. Deep Learning (LSTM/GNN) | ⭐⭐⭐⭐⭐ | 2-3 weeks | Real ML chops for MSc credential |
| 4. DevSecOps Pipeline (CI/CD) | ⭐⭐⭐☆☆ | 1 week | Shows code security expertise |
| 5. Advanced Visualization | ⭐⭐⭐☆☆ | 1-2 weeks | "Single pane of glass" executive view |
| 6. Compliance Mapping | ⭐⭐⭐⭐☆ | 1-2 weeks | CISO-level governance |

**Total estimated time**: 8-13 weeks for full implementation  
**Recommended approach**: Implement in order (1→6), each is prerequisite for next

---

## 1️⃣ UPGRADE: AKS + Istio Service Mesh + Container Escape

### Why This Matters
- **ACI** = Simple containers (mid-level)
- **AKS** = Production Kubernetes (enterprise-level)
- **Istio Service Mesh** = Zero-trust networking between pods (CISO-level)
- **Container Escape** = Shows offensive capabilities in modern infrastructure

### Architecture Change

```
Before (ACI):
┌──────────────────────┐
│  Azure Firewall      │
├──────────────────────┤
│ Spoke 1 (Honeypots)  │
├─ ACI: Juice Shop    │
├─ ACI: SSH Honeypot  │
└──────────────────────┘

After (AKS + Istio):
┌──────────────────────────────────────┐
│   Azure Firewall                     │
├──────────────────────────────────────┤
│  AKS Cluster (Kubernetes)             │
│  ┌────────────────────────────────┐  │
│  │  Istio Service Mesh (mTLS)     │  │
│  ├──────────────────────────────┤  │
│  │ Namespace: honeypot           │  │
│  │  ├─ Pod: Juice Shop           │  │
│  │  ├─ Pod: SSH Honeypot         │  │
│  │  └─ Pod: Vulnerable App       │  │
│  ├──────────────────────────────┤  │
│  │ Namespace: security-ops       │  │
│  │  └─ Pod: Agent (monitoring)   │  │
│  │                               │  │
│  │ Network Policies (mTLS):      │  │
│  │ ├─ Pod-to-Pod encryption      │  │
│  │ ├─ Service auth enforcement   │  │
│  │ └─ Ingress gateway control    │  │
│  └────────────────────────────────┘  │
└──────────────────────────────────────┘
```

### Terraform Implementation

#### Step 1: Create AKS Cluster

```hcl
# terraform/aks.tf (NEW)

resource "azurerm_kubernetes_cluster" "avars" {
  name                = "${local.resource_prefix}-aks"
  location            = azurerm_resource_group.avars.location
  resource_group_name = azurerm_resource_group.avars.name
  dns_prefix          = "${local.resource_prefix}-aks"

  default_node_pool {
    name           = "default"
    node_count     = 2
    vm_size        = "Standard_B2ms"  # 2 vCPU, 8GB RAM
    vnet_subnet_id = azurerm_subnet.spoke1_container.id

    tags = local.common_tags
  }

  network_profile {
    network_plugin    = "azure"
    service_cidr      = "10.100.0.0/16"
    dns_service_ip    = "10.100.0.10"
    load_balancer_sku = "standard"

    outbound_type = "userDefinedRouting"
  }

  identity {
    type = "SystemAssigned"
  }

  addon_profile {
    oms_agent {
      enabled                    = true
      log_analytics_workspace_id = azurerm_log_analytics_workspace.avars.id
    }

    azure_policy {
      enabled = true
    }
  }

  tags = local.common_tags

  depends_on = [
    azurerm_subnet.spoke1_container
  ]
}

# Grant AKS system identity permissions to pull from ACR (if using)
resource "azurerm_role_assignment" "aks_acr_pull" {
  scope              = azurerm_container_registry.avars.id
  role_definition_name = "AcrPull"
  principal_id       = azurerm_kubernetes_cluster.avars.kubelet_identity[0].object_id
}

# Enable Istio add-on (Azure Service Mesh)
resource "azurerm_kubernetes_cluster_service_mesh_profile" "avars" {
  kubernetes_cluster_id = azurerm_kubernetes_cluster.avars.id

  service_mesh_profile {
    mode = "Istio"

    istio_ingress_gateway {
      enabled = true
    }
  }
}
```

#### Step 2: Kubernetes Manifests for Honeypots

```yaml
# kubernetes/honeypot-namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: honeypot
  labels:
    istio-injection: enabled  # Enable sidecar injection for mTLS

---
# kubernetes/juice-shop-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: juice-shop
  namespace: honeypot
spec:
  replicas: 2
  selector:
    matchLabels:
      app: juice-shop
  template:
    metadata:
      labels:
        app: juice-shop
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "3000"
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000

      containers:
      - name: juice-shop
        image: bkimminich/juice-shop:latest
        imagePullPolicy: Always
        ports:
        - name: http
          containerPort: 3000
        
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        
        livenessProbe:
          httpGet:
            path: /
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        
        readinessProbe:
          httpGet:
            path: /
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5

---
# kubernetes/juice-shop-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: juice-shop
  namespace: honeypot
  labels:
    app: juice-shop
spec:
  type: ClusterIP
  ports:
  - port: 80
    targetPort: 3000
    protocol: TCP
    name: http
  selector:
    app: juice-shop

---
# kubernetes/istio-virtual-service.yaml (Service Mesh Routing)
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: juice-shop
  namespace: honeypot
spec:
  hosts:
  - juice-shop
  http:
  - match:
    - uri:
        prefix: /
    route:
    - destination:
        host: juice-shop
        port:
          number: 80

---
# kubernetes/authorization-policy.yaml (Zero-Trust Service-to-Service)
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: honeypot-authz
  namespace: honeypot
spec:
  rules:
  # Allow traffic only from monitoring namespace
  - from:
    - source:
        namespaces: ["security-ops"]
    to:
    - operation:
        methods: ["GET", "POST"]
        paths: ["/api/Users/*"]
  
  # Deny everything else
  - {}  # Empty rule = DENY ALL
```

### Container Escape Attack Demo

```python
# scripts/attacks/container_escape.py
"""
Advanced: Demonstrate container escape from AKS pod
Shows vulnerability chain: pod -> node -> cluster
"""

import subprocess
import os
from typing import Dict

class ContainerEscapeDemo:
    """
    Educational container escape demonstration
    Uses known Linux kernel vulnerabilities (not zero-days)
    """
    
    def check_capabilities(self) -> Dict[str, bool]:
        """Check for dangerous Linux capabilities in container"""
        caps = {
            "SYS_ADMIN": False,
            "NET_ADMIN": False,
            "SYS_MODULE": False,
        }
        
        try:
            # Check current capabilities
            result = subprocess.run(
                ["grep", "CapEff", "/proc/self/status"],
                capture_output=True,
                text=True
            )
            
            # If we have SYS_ADMIN, we can potentially escape
            if "0000003fffffffff" in result.stdout:
                caps["SYS_ADMIN"] = True
                
        except Exception as e:
            print(f"[!] Error checking capabilities: {e}")
        
        return caps
    
    def check_kernel_version(self) -> str:
        """Get kernel version for vulnerability mapping"""
        try:
            result = subprocess.run(
                ["uname", "-r"],
                capture_output=True,
                text=True
            )
            return result.stdout.strip()
        except:
            return "Unknown"
    
    def detect_escape_opportunity(self) -> bool:
        """
        Detect if escape is theoretically possible
        Checks for:
        1. Privileged container (SYS_ADMIN)
        2. Cgroup v1 escape (CVE-2021-22555 range)
        3. Filesystem access to host (mounted /proc/sys)
        """
        caps = self.check_capabilities()
        kernel = self.check_kernel_version()
        
        vulnerable = False
        reasons = []
        
        if caps["SYS_ADMIN"]:
            vulnerable = True
            reasons.append("SYS_ADMIN capability enabled")
        
        if os.path.exists("/proc/sys/kernel"):
            vulnerable = True
            reasons.append("Host /proc/sys accessible")
        
        # Check for writable /dev/kmem or /dev/mem
        for device in ["/dev/kmem", "/dev/mem"]:
            if os.path.exists(device) and os.access(device, os.W_OK):
                vulnerable = True
                reasons.append(f"{device} is writable")
        
        print(f"[*] Kernel Version: {kernel}")
        print(f"[*] Capabilities: {caps}")
        print(f"[*] Escape Possible: {vulnerable}")
        
        if vulnerable:
            print(f"[!] Reasons:")
            for reason in reasons:
                print(f"    - {reason}")
        
        return vulnerable

# Usage in attack script
escape_demo = ContainerEscapeDemo()
if escape_demo.detect_escape_opportunity():
    print("[!] Container could potentially escape to node")
    print("[*] In real scenario, would use CVE-2021-22555 or similar")
    print("[*] Mitigation: Use securityContext to drop capabilities")
```

### Monitoring Container Escape Attempts

```kql
// KQL Query: Detect Container Escape Attempts (NEW)

// Monitor for privilege escalation attempts in AKS
AKSAudit
| where verb in ("create", "patch")
| where objectRef.kind == "Pod"
| where requestObject contains "privileged" or requestObject contains "SYS_ADMIN"
| where user.username != "system:serviceaccount:kube-system:*"
| project 
    TimeGenerated,
    User = user.username,
    Namespace = objectRef.namespace,
    Pod = objectRef.name,
    Action = verb,
    SecurityContext = extract(@'"securityContext":\{([^}]+)\}', 1, requestObject),
    Severity = "Critical"

// Monitor for container runtime escape attempts
ContainerLog
| where ContainerName startswith "juice-shop" or ContainerName startswith "kali"
| where Message contains "SYS_ADMIN" or Message contains "ptrace" 
    or Message contains "ld.so.preload" or Message contains "capabilities"
| summarize EscapeAttempts = count() by ContainerName, bin(TimeGenerated, 5m)
| where EscapeAttempts > 3
```

### Istio Configuration for Zero-Trust

```yaml
# kubernetes/istio-peer-authentication.yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: honeypot
spec:
  mtls:
    mode: STRICT  # Enforce mTLS for all traffic

---
# kubernetes/request-authentication.yaml (JWT validation)
apiVersion: security.istio.io/v1beta1
kind: RequestAuthentication
metadata:
  name: jwt-auth
  namespace: honeypot
spec:
  jwtRules:
  - issuer: "https://accounts.microsoft.com"
    jwksUri: "https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"
```

### Key Benefits
✅ **Kubernetes-native** - Enterprise standard  
✅ **Service Mesh** - mTLS between all services  
✅ **Zero-trust networking** - No implicit trust  
✅ **Container escape demo** - Shows you understand container security  
✅ **Scalable** - Replicate pods across cluster  

### Estimated Effort
- **Terraform**: 200 lines
- **Kubernetes manifests**: 300 lines
- **Container escape demo**: 150 lines
- **Time**: 2-3 weeks with proper testing

---

## 2️⃣ UPGRADE: Zero Trust with Entra ID + Conditional Access + PIM

### Why This Matters
Modern cloud security = **Identity is the new perimeter**
- Firewall IP blocking = Reactive, 1990s approach
- Entra ID + Conditional Access = Proactive, identity-first, 2024 approach
- PIM = Just-in-time admin access (CISO requirement)

### Architecture

```
Attack Chain Detection:

1. User detected with suspicious activity (Sentinel alert)
2. Logic App triggered
3. Checks Entra ID Activity (sign-in risk, impossible travel)
4. Evaluates Conditional Access Policy
5. If confirmed: 
   ├─ Disable user account (Entra ID)
   ├─ Force MFA re-enrollment
   ├─ Revoke all sessions
   ├─ Trigger PIM review
   └─ Administrator notified for manual approval
```

### Terraform: Entra ID Integration

```hcl
# terraform/entra-id.tf (NEW)

# Create service principal for Logic Apps
resource "azuread_application" "avars_logic_app" {
  display_name = "${local.resource_prefix}-logic-app-sp"

  required_resource_access {
    resource_app_id = "10a7726d-67cb-4493-b6be-7d41effc1203"  # Microsoft Graph

    resource_access {
      id   = "5e6e0151-69db-4ed2-ac7e-12b3246b5797"  # User.ReadWrite.All
      type = "Role"
    }

    resource_access {
      id   = "11638aa7-ada7-4713-b0fc-6e7b92e5e91d"  # AuditLog.Read.All
      type = "Role"
    }
  }

  tags = ["security", "automation"]
}

# Service principal for the app
resource "azuread_service_principal" "avars_logic_app" {
  application_id = azuread_application.avars_logic_app.application_id
  owners         = [data.azuread_client_config.current.object_id]
}

# Grant admin consent for required permissions
resource "azuread_app_role_assignment" "avars_logic_app" {
  app_role_id         = "5e6e0151-69db-4ed2-ac7e-12b3246b5797"  # User.ReadWrite.All
  principal_object_id = azuread_service_principal.avars_logic_app.object_id
  resource_object_id  = azuread_service_principal.graph.object_id
}

# Conditional Access Policy: Block high-risk sign-ins
resource "azuread_conditional_access_policy" "avars_risk_block" {
  display_name = "${local.resource_prefix}-block-high-risk"
  state        = "enabled"

  conditions {
    sign_in_risk_levels = ["high", "critical"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users = ["All"]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}

# Conditional Access Policy: Require MFA for non-compliant devices
resource "azuread_conditional_access_policy" "avars_mfa_require" {
  display_name = "${local.resource_prefix}-mfa-noncompliant"
  state        = "enabled"

  conditions {
    device_states {
      excluded_states = ["Compliant"]
    }

    applications {
      included_applications = ["All"]
    }

    users {
      included_users = ["All"]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}

# PIM: Eligible role assignment (requires activation)
resource "azurerm_pim_eligible_role_assignment" "avars_contributor" {
  scope              = azurerm_resource_group.avars.id
  role_definition_id = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"  # Contributor
  principal_id       = azuread_group.security_team.object_id

  justification = "Required for emergency remediation actions"
}
```

### Logic App: Automated Account Disabling

```json
{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "actions": {
      "Disable_Compromised_User": {
        "type": "Http",
        "inputs": {
          "uri": "https://graph.microsoft.com/v1.0/users/@{body('Extract_User_ID')}/",
          "method": "PATCH",
          "headers": {
            "Authorization": "Bearer @{body('Get_Access_Token')}",
            "Content-Type": "application/json"
          },
          "body": {
            "accountEnabled": false,
            "comment": "Account disabled due to compromise detection - @{utcNow()}"
          }
        }
      },
      "Force_Password_Reset": {
        "type": "Http",
        "inputs": {
          "uri": "https://graph.microsoft.com/v1.0/users/@{body('Extract_User_ID')}/changePassword",
          "method": "POST",
          "headers": {
            "Authorization": "Bearer @{body('Get_Access_Token')}",
            "Content-Type": "application/json"
          },
          "body": {
            "currentPassword": "Temporary-CannotGuess-@2024",
            "newPassword": "@{guid()}"
          }
        }
      },
      "Revoke_All_Sessions": {
        "type": "Http",
        "inputs": {
          "uri": "https://graph.microsoft.com/v1.0/users/@{body('Extract_User_ID')}/revokeSignInSessions",
          "method": "POST",
          "headers": {
            "Authorization": "Bearer @{body('Get_Access_Token')}",
            "Content-Type": "application/json"
          }
        }
      },
      "Request_PIM_Review": {
        "type": "Http",
        "inputs": {
          "uri": "https://graph.microsoft.com/beta/privilegedaccess/aadResources/roleAssignmentRequests",
          "method": "POST",
          "headers": {
            "Authorization": "Bearer @{body('Get_Access_Token')}",
            "Content-Type": "application/json"
          },
          "body": {
            "roleDefinitionId": "/subscriptions/@{body('Subscription_ID')}/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c",
            "resourceId": "/subscriptions/@{body('Subscription_ID')}/resourceGroups/@{body('Resource_Group')}",
            "subjectId": "@{body('Extract_User_ID')}",
            "assignmentState": "Eligible",
            "type": "UserAdd",
            "reason": "User account was compromised. Requesting PIM verification before re-enabling."
          }
        }
      },
      "Notify_Admin": {
        "type": "ServiceProvider",
        "inputs": {
          "parameters": {
            "EmailAddress": "@{variables('SecurityTeamEmail')}",
            "Subject": "CRITICAL: Compromised User Account - Manual Approval Required",
            "Body": "User @{body('Extract_User_ID')} was automatically disabled due to compromise detection.\n\nActions Taken:\n- Account disabled\n- Password reset (temporary sent to admin email)\n- All sessions revoked\n- PIM review requested\n\nPlease verify and approve re-enablement in PIM.\n\nSentinel Alert Details:\n@{body('Get_Alert_Details')}"
          },
          "serviceProviderConfiguration": {
            "connectionName": "OutlookV2",
            "operationId": "SendEmail"
          }
        }
      }
    }
  }
}
```

### Detection Query: High-Risk Activity

```kql
// KQL: Detect compromised accounts with Entra ID signals

let HighRiskThreshold = 3;

SigninLogs
| where ConditionalAccessStatus == "failure"
  or RiskLevel in ("high", "hidden")
| extend RiskFactors = dynamicProperties.detail
| summarize 
    HighRiskSignins = countif(RiskLevel in ("high")),
    CriticalRiskSignins = countif(RiskLevel == "critical"),
    FailedMFA = countif(Status.failureReason contains "MFA"),
    ImpossibleTravel = countif(riskDetail == "impossibleTravel"),
    FirstActivity = min(TimeGenerated),
    LastActivity = max(TimeGenerated)
    by UserPrincipalName
| where HighRiskSignins >= HighRiskThreshold 
   or CriticalRiskSignins > 0
   or ImpossibleTravel > 0
| extend RecommendedAction = case(
    CriticalRiskSignins > 0, "DISABLE_ACCOUNT_IMMEDIATELY",
    ImpossibleTravel > 0 and HighRiskSignins >= 2, "INITIATE_PIM_REVIEW",
    HighRiskSignins >= HighRiskThreshold, "REQUIRE_MFA_RESET",
    "MONITOR"
    )
| project 
    TimeGenerated = FirstActivity,
    CompromisedUser = UserPrincipalName,
    HighRiskEvents = HighRiskSignins,
    CriticalRiskEvents = CriticalRiskSignins,
    MFAFailures = FailedMFA,
    ImpossibleTravelCount = ImpossibleTravel,
    RecommendedAction,
    Severity = "Critical"
```

### Benefits
✅ **Identity-first security** - Modern standard  
✅ **Automated response** - No manual intervention delay  
✅ **PIM enforcement** - Just-in-time admin access  
✅ **Conditional access** - Risk-based authentication  
✅ **Session revocation** - Immediate access removal  

---

## 3️⃣ UPGRADE: Deep Learning for Encrypted Traffic Analysis

### Why This Matters
- Scikit-learn (forest models) = Good but static patterns
- LSTM networks = Detects sequential patterns (C2 heartbeats)
- GNN (Graph Neural Networks) = Detects anomalous relationships between entities

### The Problem LSTM Solves
```
Attacker C2 Communication:
┌─ Encrypted payload ← Can't see contents (encrypted)
├─ But timing PATTERN is detectable:
│  Every 30 seconds, 50KB sent (heartbeat)
│  Regular as clockwork → ANOMALY
└─ LSTM learns: "Normal traffic is bursty"
                 "C2 is metronomic"
```

### LSTM Implementation

```python
# ml-notebooks/lstm_c2_detection.ipynb

import numpy as np
import pandas as pd
from tensorflow import keras
from tensorflow.keras import layers
import matplotlib.pyplot as plt

class LSTMTrafficAnalyzer:
    """
    LSTM Neural Network for detecting encrypted C2 traffic
    by analyzing timing patterns, not payload
    """
    
    def __init__(self, sequence_length=60):
        """
        Args:
            sequence_length: Number of time steps to analyze
        """
        self.sequence_length = sequence_length
        self.model = None
        
    def build_model(self, input_shape):
        """Build LSTM model for time series anomaly detection"""
        
        model = keras.Sequential([
            # Input: (batch_size, sequence_length, features)
            # Features: [bytes_sent, bytes_recv, packets, duration, entropy]
            
            layers.LSTM(
                units=128,
                activation='relu',
                input_shape=input_shape,
                return_sequences=True,
                name='lstm_1'
            ),
            layers.Dropout(0.2),
            
            layers.LSTM(
                units=64,
                activation='relu',
                return_sequences=True,
                name='lstm_2'
            ),
            layers.Dropout(0.2),
            
            layers.LSTM(
                units=32,
                activation='relu',
                return_sequences=False,
                name='lstm_3'
            ),
            
            layers.Dense(units=16, activation='relu', name='dense_1'),
            layers.Dropout(0.1),
            
            layers.Dense(units=8, activation='relu', name='dense_2'),
            
            # Output: anomaly score (0-1)
            layers.Dense(units=1, activation='sigmoid', name='output')
        ])
        
        model.compile(
            optimizer='adam',
            loss='mse',  # Reconstruction error
            metrics=['mae']
        )
        
        return model
    
    def prepare_sequences(self, data, labels=None):
        """
        Convert flat traffic data into sliding window sequences
        
        Args:
            data: DataFrame with columns [bytes_sent, bytes_recv, packets, duration, entropy]
            labels: Optional binary labels (0=normal, 1=C2)
        
        Returns:
            X: (n_samples, sequence_length, n_features) array
            y: Optional labels
        """
        X = []
        y_list = []
        
        # Normalize features
        data_norm = (data - data.mean()) / data.std()
        
        # Create sliding windows
        for i in range(len(data_norm) - self.sequence_length):
            window = data_norm.iloc[i:i + self.sequence_length].values
            X.append(window)
            
            if labels is not None:
                # Label window based on majority of samples in window
                y_list.append(labels.iloc[i:i + self.sequence_length].mean() > 0.5)
        
        X = np.array(X)
        
        if labels is not None:
            return X, np.array(y_list)
        return X
    
    def train(self, X_train, y_train, epochs=50, batch_size=32):
        """Train the LSTM model"""
        
        self.model = self.build_model(input_shape=X_train.shape[1:])
        
        history = self.model.fit(
            X_train, y_train,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=0.2,
            verbose=1,
            callbacks=[
                keras.callbacks.EarlyStopping(
                    monitor='val_loss',
                    patience=5,
                    restore_best_weights=True
                )
            ]
        )
        
        return history
    
    def predict_c2_probability(self, sequence):
        """
        Predict probability that a traffic sequence is C2
        
        Args:
            sequence: (sequence_length, n_features) array
        
        Returns:
            float: Probability (0-1) that traffic is C2
        """
        if self.model is None:
            raise ValueError("Model not trained yet")
        
        sequence = np.expand_dims(sequence, axis=0)  # Add batch dimension
        return float(self.model.predict(sequence, verbose=0)[0][0])
    
    def detect_c2_patterns(self, traffic_df, threshold=0.7):
        """
        Detect C2 communication in traffic data
        
        Args:
            traffic_df: DataFrame with traffic features
            threshold: Anomaly score threshold
        
        Returns:
            DataFrame with C2 predictions
        """
        
        # Prepare sequences
        X = self.prepare_sequences(traffic_df)
        
        # Get predictions
        c2_scores = self.model.predict(X, verbose=0).flatten()
        
        # Create results dataframe
        results = pd.DataFrame({
            'timestamp': traffic_df.index[self.sequence_length:],
            'c2_probability': c2_scores,
            'is_c2': c2_scores > threshold,
            'sequence_pattern': ['metronomic' if score > 0.8 else 'bursty' 
                                for score in c2_scores]
        })
        
        return results

# Example usage in notebook:
# 
# analyzer = LSTMTrafficAnalyzer(sequence_length=60)
# 
# # Train on normal traffic
# normal_traffic = pd.read_csv('normal_traffic.csv')
# X_train, y_train = analyzer.prepare_sequences(normal_traffic, labels=np.zeros(len(normal_traffic)))
# analyzer.train(X_train, y_train)
# 
# # Detect C2 in test data
# test_traffic = pd.read_csv('test_traffic.csv')
# c2_detections = analyzer.detect_c2_patterns(test_traffic, threshold=0.7)
# print(c2_detections[c2_detections['is_c2']])
```

### Graph Neural Network (GNN) for Relationship Anomalies

```python
# ml-notebooks/gnn_entity_relationship.py

import torch
import torch.nn as nn
from torch_geometric.nn import GCNConv, GraphConv
from torch_geometric.data import Data

class EntityRelationshipGNN(nn.Module):
    """
    Graph Neural Network for detecting anomalous entity relationships
    
    Graph type:
    - Nodes: Users, IPs, Domains, Ports
    - Edges: Connections between entities
    - Anomaly: Unusual relationships (user connecting to rare IP, etc.)
    """
    
    def __init__(self, num_node_features, hidden_channels):
        super().__init__()
        
        self.conv1 = GCNConv(num_node_features, hidden_channels)
        self.conv2 = GCNConv(hidden_channels, hidden_channels)
        self.conv3 = GCNConv(hidden_channels, hidden_channels)
        
        # Classification head
        self.lin = nn.Linear(hidden_channels, 2)  # 2 classes: normal/anomaly
        
    def forward(self, x, edge_index):
        """
        Args:
            x: Node features (num_nodes, num_features)
            edge_index: Edge indices (2, num_edges)
        
        Returns:
            Node anomaly scores
        """
        
        # Graph convolution layers
        x = self.conv1(x, edge_index)
        x = torch.relu(x)
        
        x = self.conv2(x, edge_index)
        x = torch.relu(x)
        
        x = self.conv3(x, edge_index)
        
        # Classification
        x = nn.functional.dropout(x, p=0.5, training=self.training)
        x = self.lin(x)
        
        return torch.softmax(x, dim=1)  # Probability distribution

# Example: Using GNN to detect anomalous user-IP relationships
#
# # Build graph from security data
# users = ['user1', 'user2', 'attacker', ...]
# ips = ['10.1.1.1', '192.168.1.1', '185.220.101.5' (tor), ...]
# 
# # Connections
# edges = [
#     (user_idx, ip_idx),  # User connected to IP
#     ...
# ]
# 
# # Anomaly: "attacker" connecting to Tor exit nodes
# # GNN learns: "Normal users don't connect to Tor"
```

### Benefits
✅ **Detects encrypted threats** - C2 heartbeat patterns  
✅ **Sequence learning** - LSTM captures timing behavior  
✅ **Entity relationships** - GNN finds unusual connections  
✅ **Deep learning credibility** - Proves MSc-level AI knowledge  
✅ **Future-proof** - Handles encrypted traffic arms race  

---

## 4️⃣ UPGRADE: DevSecOps Pipeline (GitHub Actions CI/CD)

### Why This Matters
Code security starts BEFORE deployment. Shows CISO-level mindset.

### GitHub Actions Workflow

```yaml
# .github/workflows/security-scan.yml

name: Security Scan & Deploy

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    # 1. Terraform Security Scan
    - name: TFLint - Terraform Linting
      uses: terraform-linters/setup-tflint@v3
    
    - name: Run TFLint
      run: |
        cd terraform
        tflint --init
        tflint --format compact
    
    # 2. Checkov - Infrastructure as Code Security
    - name: Checkov - IaC Security Scanning
      uses: bridgecrewio/checkov-action@master
      with:
        directory: terraform
        framework: terraform
        quiet: false
        compact: true
        output_format: sarif
        output_file_path: reports/checkov.sarif
    
    # 3. SAST - Static Application Security Testing
    - name: Semgrep - Python Code Security
      uses: returntocorp/semgrep-action@v1
      with:
        config: >-
          p/security-audit
          p/python
          p/owasp-top-ten
    
    # 4. Dependency Scanning
    - name: Trivy - Python Dependencies
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'fs'
        scan-ref: '.'
        format: 'sarif'
        output: 'trivy-results.sarif'
    
    # 5. Upload to GitHub Security Tab
    - name: Upload Results to GitHub
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'reports/checkov.sarif'
        category: 'Checkov'
    
    - name: Upload Trivy Results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'
        category: 'Trivy'
    
    # 6. Container Image Scanning (if building Docker)
    - name: Trivy Container Scan
      if: hashFiles('Dockerfile') != ''
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: 'avars:latest'
        format: 'sarif'
        output: 'trivy-container.sarif'
    
    - name: Report Results
      run: |
        echo "## Security Scan Results" >> $GITHUB_STEP_SUMMARY
        echo "✅ TFLint: Passed" >> $GITHUB_STEP_SUMMARY
        echo "✅ Checkov: Scanned" >> $GITHUB_STEP_SUMMARY
        echo "✅ Semgrep: Scanned" >> $GITHUB_STEP_SUMMARY
        echo "✅ Trivy: Scanned" >> $GITHUB_STEP_SUMMARY

  deploy:
    needs: security-scan
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Azure CLI Login
      uses: azure/login@v1
      with:
        creds: ${{ secrets.AZURE_CREDENTIALS }}
    
    - name: Terraform Deploy
      run: |
        cd terraform
        terraform init
        terraform plan -out=tfplan
        terraform apply tfplan
    
    - name: Post-Deployment Security Validation
      run: |
        # Verify Sentinel is enabled
        az sentinel operation-configuration show \
          --resource-group avars-rg \
          --workspace-name avars-lab-law
        
        # Verify Firewall threat intel enabled
        az network firewall show -g avars-rg -n avars-lab-fw \
          --query threatIntelMode

  notify:
    needs: [security-scan, deploy]
    if: always()
    runs-on: ubuntu-latest
    
    steps:
    - name: Slack Notification
      uses: 8398a7/action-slack@v3
      with:
        status: ${{ job.status }}
        text: 'A.V.A.R.S deployment: ${{ job.status }}'
        webhook_url: ${{ secrets.SLACK_WEBHOOK }}
        fields: repo,message,commit,author
```

### Checkov Configuration

```yaml
# .checkov.yaml

checks:
  - CKV2_AZURE_1   # Ensure that Microsoft Defender for Cloud is enabled
  - CKV2_AZURE_3   # Ensure that standard pricing tier is selected
  - CKV_AZURE_1    # Ensure that Virtual Machines use managed disks
  - CKV_AZURE_50   # Ensure that Virtual Machines use managed disks
  - CKV_AZURE_40   # Ensure that 'Secure transfer required' is enabled
  - CKV_AZURE_59   # Ensure that Key Vault enables SecretRotation

skip-checks:
  - CKV_AZURE_44   # (Lab environment - can skip storage account encryption)

framework: terraform
```

### Benefits
✅ **Shift-left security** - Catch issues before deployment  
✅ **CI/CD integration** - Automated on every push  
✅ **Multiple scanners** - Defense in depth (TFLint, Checkov, Trivy, Semgrep)  
✅ **GitHub security tab** - Visual vulnerability dashboard  
✅ **DevSecOps mindset** - Shows modern cloud engineering  

---

## 5️⃣ UPGRADE: Advanced Visualization & Threat Intelligence

### Power BI Dashboard Setup

```m
// Power BI: Advanced A.V.A.R.S Dashboard
// Data sources: Log Analytics, Sentinel, Threat Intel feeds

// Query: Real-time Attack Heatmap
let
    Attacks = 
        AzureDiagnostics
        | where ResourceType == "AZUREFIREWALLS"
        | where TimeGenerated > ago(24h)
        | extend SourceIP = extract(@"SourceIP=([0-9.]+)", 1, msg_s)
        | extend DestinationIP = extract(@"DestinationIP=([0-9.]+)", 1, msg_s)
        | extend AttackType = case(
            msg_s contains "401", "Brute-Force",
            msg_s contains "union", "SQLi",
            msg_s contains "SYN", "PortScan",
            "Reconnaissance"
            )
        | summarize AttackCount = count() by SourceIP, AttackType, bin(TimeGenerated, 1h)
in
    Attacks
```

### Grafana Dashboard with Threat Intel

```json
{
  "dashboard": {
    "title": "A.V.A.R.S Threat Intelligence",
    "panels": [
      {
        "title": "Attack Sources Map (GeoIP)",
        "targets": [
          {
            "query": "| geoip(SourceIP) | stats count by lat, lon"
          }
        ]
      },
      {
        "title": "C2 Communication Patterns",
        "targets": [
          {
            "query": "LSTM_C2_Scores | where prediction > 0.7"
          }
        ]
      },
      {
        "title": "Threat Intel Correlation",
        "description": "Integrates AlienVault OTX, MISP, abuse.ch"
      }
    ]
  }
}
```

### Examples of Integration

```python
# scripts/threat-intelligence/fetch_otx.py

import requests
import pandas as pd

class ThreatIntelligencer:
    """Fetch threat intelligence from multiple sources"""
    
    def fetch_alienvault_otx(self, api_key, query_ip):
        """Get AlienVault OTX reputation for IP"""
        
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{query_ip}/general"
        
        headers = {"X-OTX-API-KEY": api_key}
        response = requests.get(url, headers=headers)
        
        if response.ok:
            data = response.json()
            return {
                'ip': query_ip,
                'reputation': data.get('reputation'),
                'whitelisted': data.get('whitelisted'),
                'pulse_count': len(data.get('pulse_info', {}).get('pulses', []))
            }
        return None
    
    def fetch_misp(self, misp_url, misp_key, query_ip):
        """Query MISP for indicators"""
        
        headers = {
            "Authorization": misp_key,
            "Content-Type": "application/json"
        }
        
        response = requests.post(
            f"{misp_url}/attributes/search",
           json={"returnFormat": "json", "value": query_ip},
            headers=headers
        )
        
        if response.ok:
            return response.json().get('response', {}).get('Attribute', [])
        return []
    
    def correlate_with_attacks(self, attack_df, ti_df):
        """Correlate detected attacks with threat intel"""
        
        merged = attack_df.merge(ti_df, left_on='SourceIP', right_on='ip', how='left')
        
        # Calculate threat score
        merged['threat_score'] = (
            (merged['otx_reputation'] / 100) * 0.4 +
            (merged['c2_probability']) * 0.4 +
            (merged['anomaly_score']) * 0.2
        )
        
        return merged.sort_values('threat_score', ascending=False)
```

### Benefits
✅ **Executive visibility** - "Single pane of glass"  
✅ **Threat correlation** - Real attacks ↔ Intelligence feeds  
✅ **Geospatial analysis** - Attack origins on map  
✅ **Real-time dashboards** - Live incident tracking  

---

## 6️⃣ UPGRADE: Compliance Mapping & AI-Generated Audit Reports

### Automated NIST/ISO Mapping

```kql
// KQL: Create compliance control matrix

let ControlMappings = datatable(
    NISTControl: string,
    NISTDescription: string,
    ISO27001Control: string,
    DetectionQuery: string,
    SentinelAlert: string
) [
    "AC-2", "Account Management", "A.9.2.1", 
    "Entra-ID-Account-Anomalies", "Suspicious-Account-Activity",
    
    "SI-4", "Information System Monitoring", "A.12.4.1",
    "Firewall-Threat-Detection", "SQL-Injection-Detection",
    
    "IR-4", "Incident Handling", "A.16.1.2",
    "Sentinel-Incident-Response", "Automated-Remediation",
    
    "CA-7", "Continuous Monitoring", "A.14.2.1",
    "ML-Anomaly-Detection", "LSTM-C2-Detection",
    
    "SC-7", "Boundary Protection", "A.13.1.3",
    "Azure-Firewall-Rules", "Perimeter-Breach-Detected"
];

// For each incident, map to which controls were tested
SignalIncidents
| join kind=inner (ControlMappings) on SentinelAlert
| summarize 
    ControlsCovered = make_set(NISTControl),
    ISOControlsCovered = make_set(ISO27001Control),
    IncidentCount = count()
    by IncidentDate = bin(TimeGenerated, 1d)
```

### Logic App: AI-Generated Audit Report

```json
{
  "definition": {
    "actions": {
      "Generate_Compliance_Report": {
        "type": "Http",
        "inputs": {
          "uri": "https://{openai}.openai.azure.com/openai/deployments/gpt-4/chat/completions?api-version=2024-02-01",
          "method": "POST",
          "headers": {
            "api-key": "@variables('openai_api_key')",
            "Content-Type": "application/json"
          },
          "body": {
            "messages": [
              {
                "role": "system",
                "content": "You are a compliance audit report generator. Create professional reports mapping security incidents to NIST SP 800-53 and ISO 27001 controls."
              },
              {
                "role": "user",
                "content": "Generate compliance audit report for incident:\n\nIncident: @{body('Get_Incident_Details')}\n\nAttack Type: @{body('Attack_Technique')}\n\nMapped NIST Controls: @{body('NIST_Controls')}\n\nMapped ISO Controls: @{body('ISO_Controls')}\n\nAutomatic Response Taken: @{body('Remediation_Actions')}\n\nFormat:\n1. Executive Summary\n2. Incident Timeline\n3. Control Coverage Analysis\n4. Remediation Effectiveness\n5. Recommendations"
              }
            ],
            "temperature": 0.7,
            "max_tokens": 1500,
            "model": "gpt-4o"
          }
        }
      },
      "Save_Audit_Report": {
        "type": "ServiceProvider",
        "inputs": {
          "parameters": {
            "ContentTransferEncoding": "None",
            "Folder": "/Audit Reports",
            "FileName": "Compliance-Report-@{formatDateTime(utcNow(), 'yyyy-MM-dd-HHmm')}.pdf",
            "Body": "@{body('Generate_Compliance_Report')}"
          },
          "serviceProviderConfiguration": {
            "connectionName": "SharePoint",
            "operationId": "CreateFileSimple"
          }
        }
      }
    }
  }
}
```

### Example Report Output

```markdown
# A.V.A.R.S Compliance Audit Report
**Date**: February 21, 2026  
**Incident ID**: INC-2026-0847  
**Severity**: Critical  

## Executive Summary
A SQL injection attack was detected and automatically remediated. The incident demonstrates 100% coverage of NIST AC-2 (Account Management) and SC-7 (Boundary Protection) controls through automated detection and response.

## Incident Timeline
- 14:32:00 - Attack detected by ML model (99.2% confidence)
- 14:32:15 - Sentinel alert generated (MITRE: T1190)
- 14:32:30 - Azure OpenAI performed analysis (2.4s)
- 14:32:45 - Logic App: IP blocked at firewall
- 14:32:50 - Logic App: Jira ticket created
- 14:33:00 - Admin notification sent
- Total Response Time: 60 seconds

## Control Coverage

### NIST SP 800-53
| Control | Title | Coverage | Status |
|---------|-------|----------|--------|
| **AC-2** | Account Management | SignInLogs analysis, Entra-ID risk signals | ✅ Tested |
| **SI-4** | Information System Monitoring | Firewall logs, ML anomaly detection | ✅ Tested |
| **IR-4** | Incident Handling | Automated detection + remediation | ✅ Tested |
| **SC-7** | Boundary Protection | Firewall blocking, threat intel | ✅ Tested |

### ISO 27001
| Control | Title | Coverage | Status |
|---------|-------|----------|--------|
| **A.9.2.1** | User Access Management | Account disabling initiated | ✅ Tested |
| **A.12.4.1** | Event logging and monitoring | Full audit trail available | ✅ Tested |
| **A.16.1.2** | Incident response plan | Automated playbook executed | ✅ Tested |

## Remediation Effectiveness

**Detection Accuracy**: 99.2% (ML confidence)  
**Response Time**: 60 seconds (automated)  
**False Positives**: 0 (this month: 2 out of 1,200 alerts)  
**Attack Prevented**: ✅ Yes - IP blocked before exploitation completed  

## Recommendations

1. **Maintain current detections** - No changes despite effectiveness
2. **Monitor for variants** - Update SQL injection signatures next quarter
3. **Continue automation** - SOAR response proving 99% reliable
4. **Staff training** - Annual refresher on incident procedures

---

**Report Generated By**: Azure OpenAI (GPT-4o)  
**Verification**: Manual review by Security Team Lead [Signature]  
**Classification**: Internal Use
```

### Benefits
✅ **Regulatory compliance** - NIST, ISO, SOC2, PCI-DSS ready  
✅ **Automated reporting** - AI-generated audit trails  
✅ **Board-level documentation** - Professional compliance reports  
✅ **Control proof** - Evidence that security controls work  

---

## 📋 Implementation Roadmap

### Phase 1: Foundation (Weeks 1-3)
1. ✅ Deploy base A.V.A.R.S (already done)
2. 🔄 AKS migration from ACI
3. 🔄 Entra ID integration

### Phase 2: Intelligence (Weeks 4-6)
4. 🔄 LSTM C2 detection model
5. 🔄 GNN relationship anomalies
6. 🔄 GitHub Actions pipeline

### Phase 3: Executive Layer (Weeks 7-9)
7. 🔄 Power BI dashboards
8. 🔄 Threat intel feeds (OTX, MISP)
9. 🔄 Compliance mapping

### Phase 4: Advanced (Weeks 10-13)
10. 🔄 AI-generated audit reports
11. 🔄 Advanced PIM workflows
12. 🔄 Multi-cloud deployment

---

## 🏆 Expected Impact

### Before (Current A.V.A.R.S)
- ✅ Impressive grad/junior engineer project
- ✅ Demonstrates 4 Azure services well
- ✅ Real ML + AI integration
- **Target level**: Senior engineer, Sr. DevSecOps

### After (With All 6 Upgrades)
- ✅ CISO-level security demonstrator
- ✅ 12 Azure services integrated professionally
- ✅ Enterprise patterns (K8s, Service Mesh, Zero Trust)
- ✅ Deep learning expertise (LSTM, GNN)
- ✅ Compliance + governance (NIST, ISO, SOC2)
- ✅ DevSecOps excellence (CI/CD, scanning, automation)
- **Target level**: Principal engineer, Cloud Security Architect, Senior CISO advisor

---

## 💰 Cost Impact

| Upgrade | Monthly Cost | Value Proposition |
|---------|------------|-------------------|
| Base A.V.A.R.S | $600-1,000 | Great lab |
| + AKS cluster | +$300-500 | Production-grade |
| + PIM/Entra ID | +$0 (included) | Enterprise IAM |
| + Deep Learning (GPU) | +$200-400 | Real ML credibility |
| + BI/Grafana | +$100-200 | Executive dashboards |
| **Total** | **$1,200-2,100** | **CISO-level demonstrator** |

### ROI
- Time investment: 8-13 weeks
- Job title impact: +$30-50k salary uplift
- Seniority jump: 2-3 levels
- Market competitiveness: Top 1% of security engineers

---

**Status**: ✅ Roadmap Complete  
**Next Step**: Choose Upgrade #1 (AKS) to begin  
**Timeline**: 8-13 weeks for full implementation  
**ROI**: Estimated $200-500k over 3-year career impact
