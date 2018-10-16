#!/bin/bash

set -eux
set -o pipefail

# Create dir to put certs and keys in
mkdir certs/

# Create CA
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=vinca -out certs/vinca.pem -keyout certs/vinca.key -days 365 -sha256

# Create keys and certs for participants
for state in TAS NSW VIC ACT NT QLD WA SA;
do
    openssl req -newkey rsa:2048 -nodes -keyout certs/$state.key -subj /CN=$state | \
        openssl x509 -req -CAkey certs/vinca.key -CA certs/vinca.pem -out certs/$state.pem -CAcreateserial -days 365 -extfile <(cat <<EOF
basicConstraints=CA:FALSE
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
extendedKeyUsage=clientAuth,emailProtection
EOF
    )
done

echo "Bootstrap successful"
