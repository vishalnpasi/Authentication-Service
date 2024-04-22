#!/bin/bash

VAULT_TOKEN="$(awk 'NR==7 {print $NF}' /app/vault-keys.txt | sed 's/^[ \t]*//;s/[ \t]*$//')"

echo "$VAULT_TOKEN"

sed -i "/spring.cloud.vault.token/c\spring.cloud.vault.token=$VAULT_TOKEN" /app/src/main/resources/bootstrap-dev.properties
sed -i "/spring.cloud.vault.token/c\spring.cloud.vault.token=$VAULT_TOKEN" /app/src/main/resources/bootstrap.properties

gradle clean build -x test