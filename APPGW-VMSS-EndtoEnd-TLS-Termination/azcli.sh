 #! /bin/bash
CERT_NAME="tls-cert"
DOMAIN_NAME="clouddays.info"

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -out "${CERT_NAME}.crt" \
    -keyout "${CERT_NAME}.key" -subj "/CN=$DOMAIN_NAME/O=clouddays" \
    -addext "subjectAltName=DNS:test.$DOMAIN_NAME"

openssl pkcs12 -export -in "$CERT_NAME.crt" -inkey "$CERT_NAME.key" -out "$CERT_NAME.pfx" -passout pass:

# openssl x509 -inform PEM -in tls-cert.crt -out tls-cert.cer
# openssl x509 -in tls-cert.cer -text -noout
# cp $CERT_NAME.crt $CERT_NAME.cer
# openssl pkcs12 -in $CERT_NAME.pfx -cacerts -nokeys -out $CERT_NAME.cer -passin pass:
##############################
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

#create NSG 
az network nsg create -g $rgname -n MyNsg -l $location 

#create NSG rule 
az network nsg rule create --name Allowhttpssh --nsg-name MyNsg \
 --priority 110 --resource-group $rgname --access Allow \
 --destination-address-prefixes 10.0.2.0/24 --destination-port-ranges '*' \
 --direction Inbound --protocol Tcp --source-address-prefixes '*'

 # Create network resources 
az network vnet create \
 --name $vnetname \
 --resource-group $rgname \
 --location $location \
 --address-prefix 10.0.0.0/16 \
 --subnet-name $gatewaysubnet \
 --subnet-prefix 10.0.1.0/24 

az network vnet subnet create --name myBackendSubnet \
 --resource-group $rgname \
 --vnet-name $vnetname \
 --address-prefix 10.0.2.0/24 \
 --network-security-group MyNsg 

az network public-ip create \
 --resource-group $rgname \
 --name myAGPublicIPAddress \
 --sku Standard

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

# az vmss extension set \
#   --publisher Microsoft.Azure.Extensions \
#   --version 2.0 \
#   --name CustomScript \
#   --resource-group $rgname \
#   --vmss-name vmss \
#   --settings '{ 
#     "script": "curl -s https://raw.githubusercontent.com/ConnecttheCloud/AWSTerraformLab1/refs/heads/main/httpd-ssl.sh | bash" 
#   }'


#!/bin/bash
# Variables for Key Vault details
KEY_VAULT_NAME="tls-kv-003"
CERT_SECRET_NAME="tlscert-crt"
KEY_SECRET_NAME="tlscert-key"

# Location where Apache expects certificates
CERT_DIR="/etc/ssl/apache2"
CERT_FILE="${CERT_DIR}/apache-cert.crt"
KEY_FILE="${CERT_DIR}/apache-key.key"

# Install Apache if not installed
sudo yum install -y httpd mod_ssl

# Create certificate directory
sudo mkdir -p ${CERT_DIR}

# Install Azure CLI to interact with Key Vault (if needed)
# curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
sudo dnf install -y https://packages.microsoft.com/config/rhel/8/packages-microsoft-prod.rpm
sudo dnf install azure-cli -y

# Login with managed identity
az login --identity

# Fetch certificate and key from Key Vault
CERT_CONTENT=$(az keyvault secret show --vault-name $KEY_VAULT_NAME --name $CERT_SECRET_NAME --query value -o tsv)
KEY_CONTENT=$(az keyvault secret show --vault-name $KEY_VAULT_NAME --name $KEY_SECRET_NAME --query value -o tsv)

# Write the certificate and key to files
echo "$CERT_CONTENT" | sudo tee $CERT_FILE
echo "$KEY_CONTENT" | sudo tee $KEY_FILE

# Set correct permissions
sudo chmod 600 $CERT_FILE $KEY_FILE
sudo chown root:root $CERT_FILE $KEY_FILE

# Configure Apache for HTTPS
sudo bash -c 'cat <<EOF > /etc/httpd/conf.d/ssl.conf
Listen 443 https

<VirtualHost *:443>
    ServerName test.clouddays.info
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html
    DirectoryIndex index.html index.php
    SSLEngine on
    SSLCertificateFile /etc/ssl/apache2/apache-cert.crt
    SSLCertificateKeyFile /etc/ssl/apache2/apache-key.key

    <Directory "/var/www/html">
        AllowOverride All
    </Directory>

    ErrorLog logs/ssl_error_log
    TransferLog logs/ssl_access_log
</VirtualHost>

<VirtualHost *:80>
  ServerName test.clouddays.info
  Redirect / https://test.clouddays.info/
</VirtualHost>  

EOF'

# Enable and start Apache
sudo systemctl enable httpd
sudo systemctl start httpd
