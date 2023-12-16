import uuid
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient

# Information required to authenticate using a Service Principal
tenant_id = "84f1e4ea-8554-43e1-8709-f0b8589ea118"
client_id = "19d4a554-d272-4f0b-9b5f-f70bf4132212"
client_secret = "sdP8Q~MBu0ehJOEgBBLtpnECfXPcnLji~XJIEaYB"

# Information for the Key Vault
keyVaultName = "keyvault2567890"
keyVaultUri = f"https://{keyVaultName}.vault.azure.net"

# Get the application credentials
app_credentials = ClientSecretCredential(tenant_id, client_id, client_secret) 
# Connect to Key Vault using app credentials
client = SecretClient(vault_url=keyVaultUri, credential=app_credentials)

# Check whether student has created a secret in KV to retrieve
existingSecretCreated = input("\nWould you like to retrieve an existing secret? (Y/N):  ")
if existingSecretCreated.strip() in ('Y', 'y'):
  # Let's read the secret
  existingSecretName = input("What is the name of the existing secret:  ")
  print(f"Now retrieving existing secret, '{existingSecretName.strip()}' from {keyVaultName}...", end=' '),
  try:
    existingSecret = client.get_secret(existingSecretName.strip())
  except Exception as readEx:
    print("\tERROR\n")
    print(f"{readEx}\n\nMoving on to next step ...\n")
  else:
    print("\tOK!\n")
    print(f"The existing secret in {keyVaultName}, called '{existingSecretName}, has a value of '{existingSecret.value}'\n")

if existingSecretCreated.strip() in ('N', 'n'):
	print("Not checking existing secret ...\n")

# Would you like to create a new secret?
newSecret = input("Would you like to create a new secret? (Y/N): ")
if newSecret.strip() in ('Y', 'y'):
  # Let's create it
  newSecretName = input("Enter a name for your new secret:  ")
  newSecretValue = input("Enter a value for your new secret:  ")

  # Create the new secret
  print(f"Now creating a new secret in {keyVaultName}, called '{newSecretName.strip()}', with value '{newSecretValue}' ...", end=' ')
  try:
    client.set_secret(newSecretName.strip(), newSecretValue)
  except Exception as writeEx:
    print("\tERROR\n")
    print(f"{writeEx}\n\n")
  else:    
    print("\tOK!\n")

print ("\nAll done. Goodbye!")
