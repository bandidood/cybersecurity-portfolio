# Industrial IoT Cloud Infrastructure
# Terraform configuration for automated cloud deployment
# Supports Azure, AWS, and hybrid deployments

terraform {
  required_version = ">= 1.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1"
    }
  }
  
  backend "azurerm" {
    resource_group_name  = "rg-terraform-state"
    storage_account_name = "satfstateiot2024"
    container_name       = "tfstate"
    key                  = "industrial-iot.tfstate"
  }
}

# Provider configurations
provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
    key_vault {
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = true
    }
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "Industrial-IoT-Platform"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = var.owner
    }
  }
}

# Local values
locals {
  project_name = "industrial-iot"
  common_tags = {
    Project     = "Industrial-IoT-Platform"
    Environment = var.environment
    ManagedBy   = "Terraform"
    Owner       = var.owner
    CostCenter  = var.cost_center
  }
  
  # Naming convention
  resource_prefix = "${local.project_name}-${var.environment}"
  
  # Network configuration
  azure_vnet_cidr = "10.0.0.0/16"
  aws_vpc_cidr    = "10.1.0.0/16"
  
  # Capacity configuration based on environment
  capacity_config = {
    dev = {
      iot_hub_units           = 1
      iot_hub_sku            = "S1"
      cosmosdb_throughput    = 400
      storage_replication    = "LRS"
      vm_size                = "Standard_B2s"
      auto_scaling_min       = 1
      auto_scaling_max       = 3
    }
    staging = {
      iot_hub_units           = 2
      iot_hub_sku            = "S1"
      cosmosdb_throughput    = 800
      storage_replication    = "GRS"
      vm_size                = "Standard_D2s_v3"
      auto_scaling_min       = 2
      auto_scaling_max       = 5
    }
    production = {
      iot_hub_units           = 3
      iot_hub_sku            = "S2"
      cosmosdb_throughput    = 1000
      storage_replication    = "GRS"
      vm_size                = "Standard_D4s_v3"
      auto_scaling_min       = 3
      auto_scaling_max       = 10
    }
  }
  
  current_capacity = local.capacity_config[var.environment]
}

# Random password generation
resource "random_password" "db_passwords" {
  for_each = toset(["influxdb", "mongodb", "redis"])
  
  length  = 32
  special = true
}

#############################################################################
# AZURE RESOURCES
#############################################################################

# Resource Group
resource "azurerm_resource_group" "main" {
  name     = "rg-${local.resource_prefix}"
  location = var.azure_location
  tags     = local.common_tags
}

# Virtual Network
resource "azurerm_virtual_network" "main" {
  name                = "vnet-${local.resource_prefix}"
  address_space       = [local.azure_vnet_cidr]
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.common_tags
}

# Subnets
resource "azurerm_subnet" "iot" {
  name                 = "subnet-iot"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_subnet" "compute" {
  name                 = "subnet-compute"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.2.0/24"]
}

resource "azurerm_subnet" "data" {
  name                 = "subnet-data"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.3.0/24"]
}

# Network Security Groups
resource "azurerm_network_security_group" "iot" {
  name                = "nsg-${local.resource_prefix}-iot"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  
  # IoT Hub communication
  security_rule {
    name                       = "Allow-IoT-MQTT"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "8883"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  
  security_rule {
    name                       = "Allow-IoT-HTTPS"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  
  tags = local.common_tags
}

resource "azurerm_network_security_group" "compute" {
  name                = "nsg-${local.resource_prefix}-compute"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  
  # API Gateway
  security_rule {
    name                       = "Allow-API-HTTPS"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  
  # Prometheus monitoring
  security_rule {
    name                       = "Allow-Prometheus"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "9090"
    source_address_prefix      = "10.0.0.0/16"
    destination_address_prefix = "*"
  }
  
  tags = local.common_tags
}

# Associate NSGs with Subnets
resource "azurerm_subnet_network_security_group_association" "iot" {
  subnet_id                 = azurerm_subnet.iot.id
  network_security_group_id = azurerm_network_security_group.iot.id
}

resource "azurerm_subnet_network_security_group_association" "compute" {
  subnet_id                 = azurerm_subnet.compute.id
  network_security_group_id = azurerm_network_security_group.compute.id
}

# IoT Hub
resource "azurerm_iothub" "main" {
  name                = "iot-${local.resource_prefix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  
  sku {
    name     = local.current_capacity.iot_hub_sku
    capacity = local.current_capacity.iot_hub_units
  }
  
  # Device-to-cloud endpoints
  endpoint {
    type                       = "AzureIotHub.EventHub"
    connection_string          = azurerm_eventhub_authorization_rule.iot_events.primary_connection_string
    name                       = "export"
    batch_frequency_in_seconds = 60
    max_chunk_size_in_bytes    = 10485760
    container_name             = azurerm_storage_container.iot_data.name
    file_name_format           = "{iothub}/{partition}/{YYYY}/{MM}/{DD}/{HH}/{mm}"
    encoding                   = "Avro"
  }
  
  # Routes for different message types
  route {
    name           = "DeviceTelemetryToDefault"
    source         = "DeviceMessages"
    condition      = "true"
    endpoint_names = ["events"]
    enabled        = true
  }
  
  route {
    name           = "DeviceAlertsToEventHub"
    source         = "DeviceMessages"
    condition      = "messageType = 'alert'"
    endpoint_names = ["export"]
    enabled        = true
  }
  
  # Message enrichments
  enrichment {
    key            = "location"
    value          = "$twin.tags.location"
    endpoint_names = ["events", "export"]
  }
  
  enrichment {
    key            = "deviceType"
    value          = "$twin.tags.deviceType"
    endpoint_names = ["events", "export"]
  }
  
  tags = local.common_tags
}

# Event Hub Namespace for IoT data processing
resource "azurerm_eventhub_namespace" "main" {
  name                = "evhns-${local.resource_prefix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "Standard"
  capacity            = 2
  
  auto_inflate_enabled     = true
  maximum_throughput_units = 10
  
  tags = local.common_tags
}

resource "azurerm_eventhub" "iot_events" {
  name                = "iot-events"
  namespace_name      = azurerm_eventhub_namespace.main.name
  resource_group_name = azurerm_resource_group.main.name
  partition_count     = 4
  message_retention   = 7
}

resource "azurerm_eventhub_authorization_rule" "iot_events" {
  name                = "SendRule"
  namespace_name      = azurerm_eventhub_namespace.main.name
  eventhub_name       = azurerm_eventhub.iot_events.name
  resource_group_name = azurerm_resource_group.main.name
  listen              = false
  send                = true
  manage              = false
}

# Storage Account for data lake
resource "azurerm_storage_account" "datalake" {
  name                          = "sa${replace(local.resource_prefix, "-", "")}dl"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = azurerm_resource_group.main.location
  account_tier                  = "Standard"
  account_replication_type      = local.current_capacity.storage_replication
  is_hns_enabled               = true  # Data Lake Gen2
  enable_https_traffic_only     = true
  min_tls_version              = "TLS1_2"
  
  blob_properties {
    versioning_enabled       = true
    last_access_time_enabled = true
    
    delete_retention_policy {
      days = 30
    }
    
    container_delete_retention_policy {
      days = 30
    }
  }
  
  network_rules {
    default_action             = "Deny"
    virtual_network_subnet_ids = [azurerm_subnet.data.id]
    ip_rules                   = var.admin_ip_addresses
  }
  
  tags = local.common_tags
}

# Storage containers
resource "azurerm_storage_container" "iot_data" {
  name                  = "iot-telemetry"
  storage_account_name  = azurerm_storage_account.datalake.name
  container_access_type = "private"
}

resource "azurerm_storage_container" "ml_models" {
  name                  = "ml-models"
  storage_account_name  = azurerm_storage_account.datalake.name
  container_access_type = "private"
}

resource "azurerm_storage_container" "backups" {
  name                  = "backups"
  storage_account_name  = azurerm_storage_account.datalake.name
  container_access_type = "private"
}

# Cosmos DB for metadata and configuration
resource "azurerm_cosmosdb_account" "main" {
  name                = "cosmos-${local.resource_prefix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"
  
  enable_automatic_failover = var.environment == "production"
  
  consistency_policy {
    consistency_level       = "BoundedStaleness"
    max_interval_in_seconds = 300
    max_staleness_prefix    = 100000
  }
  
  geo_location {
    location          = azurerm_resource_group.main.location
    failover_priority = 0
  }
  
  dynamic "geo_location" {
    for_each = var.environment == "production" ? [1] : []
    content {
      location          = var.azure_secondary_location
      failover_priority = 1
    }
  }
  
  tags = local.common_tags
}

resource "azurerm_cosmosdb_sql_database" "iot_metadata" {
  name                = "iot-metadata"
  resource_group_name = azurerm_resource_group.main.name
  account_name        = azurerm_cosmosdb_account.main.name
  throughput          = local.current_capacity.cosmosdb_throughput
}

resource "azurerm_cosmosdb_sql_container" "devices" {
  name                = "devices"
  resource_group_name = azurerm_resource_group.main.name
  account_name        = azurerm_cosmosdb_account.main.name
  database_name       = azurerm_cosmosdb_sql_database.iot_metadata.name
  partition_key_path  = "/deviceId"
  throughput          = 400
  
  indexing_policy {
    indexing_mode = "Consistent"
    
    included_path {
      path = "/*"
    }
    
    excluded_path {
      path = "/telemetry/*"
    }
  }
}

# Key Vault for secrets management
resource "azurerm_key_vault" "main" {
  name                       = "kv-${local.resource_prefix}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = var.environment == "production"
  
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    ip_rules       = var.admin_ip_addresses
    virtual_network_subnet_ids = [
      azurerm_subnet.compute.id,
      azurerm_subnet.data.id
    ]
  }
  
  tags = local.common_tags
}

# Key Vault access policy
resource "azurerm_key_vault_access_policy" "main" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = data.azurerm_client_config.current.object_id
  
  secret_permissions = [
    "Get", "List", "Set", "Delete", "Purge", "Recover", "Backup", "Restore"
  ]
  
  key_permissions = [
    "Get", "List", "Create", "Delete", "Update", "Import", "Backup", "Restore", "Recover"
  ]
}

# Store database passwords in Key Vault
resource "azurerm_key_vault_secret" "db_passwords" {
  for_each = random_password.db_passwords
  
  name         = "${each.key}-password"
  value        = each.value.result
  key_vault_id = azurerm_key_vault.main.id
  
  depends_on = [azurerm_key_vault_access_policy.main]
  
  tags = local.common_tags
}

# Container Registry for ML models and applications
resource "azurerm_container_registry" "main" {
  name                = "acr${replace(local.resource_prefix, "-", "")}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "Premium"
  admin_enabled       = true
  
  network_rule_set {
    default_action = "Deny"
    
    virtual_network {
      action    = "Allow"
      subnet_id = azurerm_subnet.compute.id
    }
    
    dynamic "ip_rule" {
      for_each = var.admin_ip_addresses
      content {
        action   = "Allow"
        ip_range = ip_rule.value
      }
    }
  }
  
  tags = local.common_tags
}

# Azure Kubernetes Service for ML workloads
resource "azurerm_kubernetes_cluster" "main" {
  name                = "aks-${local.resource_prefix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  dns_prefix          = "aks-${local.resource_prefix}"
  kubernetes_version  = var.kubernetes_version
  
  default_node_pool {
    name                = "system"
    node_count          = local.current_capacity.auto_scaling_min
    vm_size             = local.current_capacity.vm_size
    zones               = ["1", "2", "3"]
    enable_auto_scaling = true
    min_count          = local.current_capacity.auto_scaling_min
    max_count          = local.current_capacity.auto_scaling_max
    vnet_subnet_id     = azurerm_subnet.compute.id
    
    upgrade_settings {
      max_surge = "10%"
    }
  }
  
  identity {
    type = "SystemAssigned"
  }
  
  network_profile {
    network_plugin     = "azure"
    network_policy     = "azure"
    dns_service_ip     = "10.2.0.10"
    docker_bridge_cidr = "172.17.0.1/16"
    service_cidr       = "10.2.0.0/24"
  }
  
  auto_scaler_profile {
    balance_similar_node_groups = true
    max_graceful_termination_sec = 600
    scale_down_delay_after_add = "10m"
    scale_down_unneeded = "10m"
    
    # Resource limits
    max_node_provision_time = "15m"
    max_unready_nodes = 3
    max_unready_percentage = 45
  }
  
  azure_policy_enabled = true
  
  monitor_metrics {
    annotations_allowed = null
    labels_allowed      = null
  }
  
  tags = local.common_tags
}

# Additional node pool for ML workloads with GPU
resource "azurerm_kubernetes_cluster_node_pool" "ml_gpu" {
  count = var.enable_gpu_nodes ? 1 : 0
  
  name                  = "mlgpu"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.main.id
  vm_size               = "Standard_NC6s_v3"  # GPU enabled
  node_count            = 1
  min_count            = 0
  max_count            = 3
  enable_auto_scaling   = true
  zones                = ["1", "2", "3"]
  vnet_subnet_id       = azurerm_subnet.compute.id
  
  node_labels = {
    "workload" = "ml-gpu"
  }
  
  node_taints = [
    "workload=ml-gpu:NoSchedule"
  ]
  
  tags = local.common_tags
}

# Log Analytics Workspace for monitoring
resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-${local.resource_prefix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = var.environment == "production" ? 90 : 30
  
  tags = local.common_tags
}

# Application Insights for application monitoring
resource "azurerm_application_insights" "main" {
  name                = "ai-${local.resource_prefix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  workspace_id        = azurerm_log_analytics_workspace.main.id
  application_type    = "web"
  
  tags = local.common_tags
}

#############################################################################
# AWS RESOURCES (Hybrid setup)
#############################################################################

# VPC for AWS resources
resource "aws_vpc" "main" {
  count = var.enable_aws_resources ? 1 : 0
  
  cidr_block           = local.aws_vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-vpc"
  })
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  count = var.enable_aws_resources ? 1 : 0
  
  vpc_id = aws_vpc.main[0].id
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-igw"
  })
}

# Subnets
resource "aws_subnet" "private" {
  count = var.enable_aws_resources ? 2 : 0
  
  vpc_id            = aws_vpc.main[0].id
  cidr_block        = "10.1.${count.index + 1}.0/24"
  availability_zone = data.aws_availability_zones.available[0].names[count.index]
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-private-${count.index + 1}"
    Type = "Private"
  })
}

resource "aws_subnet" "public" {
  count = var.enable_aws_resources ? 2 : 0
  
  vpc_id                  = aws_vpc.main[0].id
  cidr_block              = "10.1.${count.index + 10}.0/24"
  availability_zone       = data.aws_availability_zones.available[0].names[count.index]
  map_public_ip_on_launch = true
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-public-${count.index + 1}"
    Type = "Public"
  })
}

# NAT Gateway for private subnets
resource "aws_eip" "nat" {
  count = var.enable_aws_resources ? 1 : 0
  
  domain = "vpc"
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-nat-eip"
  })
}

resource "aws_nat_gateway" "main" {
  count = var.enable_aws_resources ? 1 : 0
  
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-nat"
  })
  
  depends_on = [aws_internet_gateway.main]
}

# Route tables
resource "aws_route_table" "public" {
  count = var.enable_aws_resources ? 1 : 0
  
  vpc_id = aws_vpc.main[0].id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main[0].id
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-public-rt"
  })
}

resource "aws_route_table" "private" {
  count = var.enable_aws_resources ? 1 : 0
  
  vpc_id = aws_vpc.main[0].id
  
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[0].id
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-private-rt"
  })
}

# Route table associations
resource "aws_route_table_association" "public" {
  count = var.enable_aws_resources ? 2 : 0
  
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_route_table_association" "private" {
  count = var.enable_aws_resources ? 2 : 0
  
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[0].id
}

# AWS IoT Core
resource "aws_iot_thing_type" "industrial_sensor" {
  count = var.enable_aws_resources ? 1 : 0
  
  name = "IndustrialSensor"
  
  properties {
    description = "Industrial IoT sensors for manufacturing"
  }
  
  tags = local.common_tags
}

# AWS TimeStream for time-series data
resource "aws_timestreamwrite_database" "iot_data" {
  count = var.enable_aws_resources ? 1 : 0
  
  database_name = replace("${local.resource_prefix}-iot-data", "-", "_")
  
  tags = local.common_tags
}

resource "aws_timestreamwrite_table" "sensor_data" {
  count = var.enable_aws_resources ? 1 : 0
  
  database_name = aws_timestreamwrite_database.iot_data[0].database_name
  table_name    = "sensor_readings"
  
  retention_properties {
    memory_store_retention_period_in_hours  = 24
    magnetic_store_retention_period_in_days = 365
  }
  
  tags = local.common_tags
}

#############################################################################
# DATA SOURCES
#############################################################################

data "azurerm_client_config" "current" {}

data "aws_availability_zones" "available" {
  count = var.enable_aws_resources ? 1 : 0
  state = "available"
}

data "aws_caller_identity" "current" {
  count = var.enable_aws_resources ? 1 : 0
}