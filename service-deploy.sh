#!/bin/bash

echo "Setting vault token to env"

SPRING_CLOUD_VAULT_TOKEN="$(awk 'NR==7 {print $NF}' /app/vault-keys.txt | sed 's/^[ \t]*//;s/[ \t]*$//')"

export SPRING_CLOUD_VAULT_TOKEN

echo "Vault token set"

echo "Running java service"

java -jar /app/build/libs/authentication-service.jar


#while true; do sleep 1; done
