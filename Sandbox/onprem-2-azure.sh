#!/bin/bash
#vmr
# Variables
location="southafricanorth"
resourceGroup="rg3-hybrid-network"
vnetName="vnet-hybrid"
subnetName="subnet-gateway"
gatewaySubnetName="GatewaySubnet"
onPremVnetName="vnet-onprem"
onPremSubnetName="subnet-onprem"
vpnGatewayName="vpn-gateway"
localGatewayName="local-gateway"
connectionName="vpn-connection"
sharedKey="MySharedKey123"
tagEnvironment="HybridTest"
tagOwner="Vince.Resente"

# Create Resource Group
az group create \
  --name $resourceGroup \
  --location $location \
  --tags Environment=$tagEnvironment Owner=$tagOwner

# Create Azure VNet and Gateway Subnet
az network vnet create \
  --resource-group $resourceGroup \
  --name $vnetName \
  --address-prefixes 10.1.0.0/16 \
  --subnet-name $subnetName \
  --subnet-prefix 10.1.1.0/24

az network vnet subnet create \
  --resource-group $resourceGroup \
  --vnet-name $vnetName \
  --name $gatewaySubnetName \
  --address-prefix 10.1.255.0/27

# Simulate On-Premises VNet
az network vnet create \
  --resource-group $resourceGroup \
  --name $onPremVnetName \
  --address-prefixes 10.2.0.0/16 \
  --subnet-name $onPremSubnetName \
  --subnet-prefix 10.2.1.0/24

# Create Public IP for VPN Gateway (must be Static for Standard SKU)
az network public-ip create \
  --resource-group $resourceGroup \
  --name "${vpnGatewayName}-pip" \
  --sku Standard \
  --allocation-method Static
  # Optionally add: --zone 1 2 3 (if region supports zone-redundant IPs)

# Create VPN Gateway
az network vnet-gateway create \
  --resource-group $resourceGroup \
  --name $vpnGatewayName \
  --public-ip-address "${vpnGatewayName}-pip" \
  --vnet $vnetName \
  --gateway-type Vpn \
  --vpn-type RouteBased \
  --sku VpnGw1 \
  --no-wait \
  --location $location

# Create Local Network Gateway (simulated on-prem)
az network local-gateway create \
  --resource-group $resourceGroup \
  --name $localGatewayName \
  --gateway-ip-address "203.0.113.1" \
  --local-address-prefixes "10.2.0.0/16"

# Create VPN Connection
az network vpn-connection create \
  --resource-group $resourceGroup \
  --name $connectionName \
  --vnet-gateway1 $vpnGatewayName \
  --local-gateway2 $localGatewayName \
  --shared-key $sharedKey \
  --enable-bgp false

# Tagging VPN Gateway explicitly
az resource tag \
  --tags Environment=$tagEnvironment Owner=$tagOwner \
  --ids $(az resource show \
    --resource-group $resourceGroup \
    --name $vpnGatewayName \
    --resource-type "Microsoft.Network/virtualNetworkGateways" \
    --query id -o tsv)
