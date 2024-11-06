# CloudNativeLab- [CloudNativeLab](#cloudnativelab)

This is the end to end TLS termination of Azure App gateway and VMSS where apache web servers are running. 

## Deployment Steps

1) Create Resoruce Group, Application Gateway, Key Vault, User Assigned Manage Identity and VMSS
2) Create self-signed certificate and key
3) Upload certificate and key to Azure Keyvault 
4) Assign requreid permission to access keyvault and attached to APP Gateway and VMSS
5) Configure TLS end to end encryption

The following is the complete Azcli command to complete this lab.

### Create Self sigend certificate
```
 #! /bin/bash
CERT_NAME="tls-cert"
DOMAIN_NAME="clouddays.info"

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -out "${CERT_NAME}.crt" \
    -keyout "${CERT_NAME}.key" -subj "/CN=$DOMAIN_NAME/O=clouddays" \
    -addext "subjectAltName=DNS:test.$DOMAIN_NAME"

openssl pkcs12 -export -in "$CERT_NAME.crt" -inkey "$CERT_NAME.key" -out "$CERT_NAME.pfx" -passout pass:
```

### Create Azure Resources APP Gateway, Keyvault, VMSS and fetch certificate from key vault
```
location=westus
rgname=RG001-westus 
vnetname=VNet001-westus 
gatewaysubnet=myAGSubnet 
appgatewayname=APPGW001 
identity_name=appgw-kv-userid
kv_name=tls-kv-003

# Create a resource group 
az group create --name $rgname --location $location

#### Create Key Vault
az keyvault create -l $location --name $kv_name --resource-group $rgname --enable-rbac-authorization true

# Create User Assigned MID
az identity create --name $identity_name --resource-group $rgname --location $location 

# Get the Object ID of the managed identity & Assign KV Secret user role
IDENTITY_ID=$(az identity show --name $identity_name --resource-group $rgname --query principalId --output tsv)

az role assignment create --assignee-object-id $IDENTITY_ID --assignee-principal-type ServicePrincipal \
  --role "Key Vault Secrets User" --scope $(az keyvault show --name $kv_name --resource-group $rgname --query id --output tsv)

# Assign KV priviliged to myuser account
IDENTITY_USER=$(az ad signed-in-user show --query userPrincipalName --output tsv)
az role assignment create --assignee $IDENTITY_USER --role "Key Vault Administrator" \
  --scope $(az keyvault show --name $kv_name --resource-group $rgname --query id --output tsv)

az keyvault certificate import --vault-name $kv_name --name tlscert-pfx --file $CERT_NAME.pfx 
 # --password <pfx-password>

az keyvault secret set --vault-name $kv_name --name tlscert-crt --file ${CERT_NAME}.crt

az keyvault secret set --vault-name $kv_name --name tlscert-key --file $CERT_NAME.key

# create NSG 
az network nsg create -g $rgname -n MyNsg -l $location 

# create NSG rule 
az network nsg rule create --name Allowhttpssh --nsg-name MyNsg \
 --priority 110 --resource-group $rgname --access Allow \
 --destination-address-prefixes 10.0.2.0/24 --destination-port-ranges '*' \
 --direction Inbound --protocol Tcp --source-address-prefixes '*'

 # Create network resources 
az network vnet create \
 --name $vnetname --resource-group $rgname \
 --location $location --address-prefix 10.0.0.0/16 \
 --subnet-name $gatewaysubnet --subnet-prefix 10.0.1.0/24 

az network vnet subnet create --name myBackendSubnet \
 --resource-group $rgname --vnet-name $vnetname \
 --address-prefix 10.0.2.0/24 --network-security-group MyNsg 

az network public-ip create --resource-group $rgname --name myAGPublicIPAddress --sku Standard

 # az identity show --name $identity_name --resource-group $rgname --query id --output tsv
ManagedIdentity_ID=$(az identity show --name $identity_name --resource-group $rgname --query id --output tsv)

 az network application-gateway create --name $appgatewayname \
    --resource-group $rgname --location $location \
    --sku Standard_v2 --capacity 1 \
    --public-ip-address myAGPublicIPAddress --vnet-name $vnetname \
    --subnet $gatewaysubnet \
    --identity $ManagedIdentity_ID --priority 1001

# Create TLS Cert
SECRET_ID=$(az keyvault secret show --vault-name $kv_name --name tlscert-pfx --query "id" -o tsv)

az network application-gateway ssl-cert create --gateway-name $appgatewayname \
    --resource-group $rgname --name MySslCert --key-vault-secret-id $SECRET_ID

# Create Frontend port 
az network application-gateway frontend-port create \
  --gateway-name $appgatewayname --resource-group $rgname \
  --name FrontendPort443 --port 443

# Create 443 Listener 
az network application-gateway http-listener create --gateway-name $appgatewayname \
    --resource-group $rgname --name MyHttpsListener \
    --frontend-port FrontendPort443 --frontend-ip appGatewayFrontendIP \
    --ssl-cert MySslCert 

# Create Root Cert for Backend Setting
SECRET_ID=$(az keyvault certificate show --vault-name $kv_name --name tlscert-pfx --query "sid" -o tsv)

az network application-gateway root-cert create \
  --gateway-name $appgatewayname --resource-group $rgname \
  --name root-cert --keyvault-secret $SECRET_ID

# Check Root Cert
az network application-gateway root-cert list -g $rgname --gateway-name $appgatewayname 

# Create 443 Backend setting
ROOT_CERT_ID=$(az network application-gateway root-cert list --resource-group $rgname \
  --gateway-name $appgatewayname --query "[?name=='root-cert'].id" -o tsv)

az network application-gateway http-settings create \
  --gateway-name $appgatewayname --resource-group $rgname \
  --name MyBackendHttpsSettings --port 443 --protocol Https \
  --host-name test.clouddays.info --root-certs $ROOT_CERT_ID

# Create rule
az network application-gateway rule create --gateway-name $appgatewayname \
    --resource-group $rgname --name MyHttpsRule \
    --http-listener MyHttpsListener --rule-type Basic  --priority 100 --http-settings MyBackendHttpsSettings

# Setup NAT Gateway for outbound 
az network public-ip create --resource-group $rgname \
  --name myPublicIP --sku Standard --allocation-method Static

az network nat gateway create --resource-group $rgname \
  --name myNatGateway --public-ip-addresses myPublicIP 
  
az network vnet subnet update \
  --resource-group $rgname \
  --vnet-name $vnetname \
  --name myBackendSubnet \
  --nat-gateway myNatGateway

 #solvedevops1643693563360:alma-linux-9:plan001:2023.06.02
 #solvedevops1643693563360:rocky-linux-9:plan001
# Create a virtual machine scale set Alma 9 image 
az vmss create \
 --resource-group $rgname \
 --name vmss \
 --image CentOS85Gen2 \
 --admin-username azureuser  \
 --admin-password P@ssw0rd1234567 \
 --authentication-type password \
 --instance-count 2 \
 --vnet-name $vnetname \
 --subnet myBackendSubnet \
 --vm-sku Standard_B1s \
 --upgrade-policy-mode Automatic \
 --assign-identity $ManagedIdentity_ID \
 --app-gateway $appgatewayname \
 --backend-pool-name appGatewayBackendPool \
 --storage-sku Standard_LRS \
 --custom-data custom-data.txt 

# Install Apache 
az vmss extension set \
 --publisher Microsoft.Azure.Extensions \
 --version 2.0 --name CustomScript \
 --resource-group $rgname --vmss-name vmss \
 --settings '{ "fileUris": ["https://raw.githubusercontent.com/ConnecttheCloud/AWSTerraformLab1/refs/heads/main/httpd-ssl.sh"], "commandToExecute": "./httpd-ssl.sh" }'
 ```


Here is the web portal and loadbalancing from VMSS VM:

![Web1](./images/web1-image.jpg)


![Web2](./images/web2-image.jpg)

Below are created Azure resources:

![Azure Resoruces](./images/azureresources.jpg)
