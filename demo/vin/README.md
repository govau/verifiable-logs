# VIN demo

This application provides a service whereby participants can submit updates to a centralised ledger for updates to which jurisdiction has a vehicle (identified by VIN) registered to it.

## Get source

```bash
# ignore warning about no buildable files
go get github.com/govau/verifiable-logs/demo/vin
cd ${GOPATH-$HOME/go}/src/github.com/govau/verifiable-logs/demo/vin
dep ensure
```

## Bootstrap certs

Before deploying, we create a simple CA, and we use this to issue a client certificate to each jurisdiction:

```bash
# Bootstrap
./bootstrap-certs.sh
```

Creates (in `certs/` directory):

```
ACT.key
ACT.pem
NSW.key
NSW.pem
NT.key
NT.pem
QLD.key
QLD.pem
SA.key
SA.pem
TAS.key
TAS.pem
VIC.key
VIC.pem
vinca.key
vinca.pem
vinca.srl
WA.key
WA.pem
```

## Run the server

TO test the server locally, not persisting anything to a real database:

```bash
NODB=1 VINCA_PEM=$(cat certs/vinca.pem) PORT=8080 go run app/main.go
```

## Send record to server

We use a simple JSON structure for each record, then sign it with the X509 certificate generated above and POST this to our server.

Our server implements [RFC6962](https://tools.ietf.org/html/rfc6962) with a custom type for the CMS signed data instead of a regular X509 certificate.

Locally:

```bash
echo "{\"timestamp\":\"$(date --iso-8601=seconds)\",\"jurisdiction\":\"NSW\",\"vin\":\"VIN0123456789\"}" | \
    openssl cms -sign -signer certs/NSW.pem -inkey certs/NSW.key -outform DER -stream | \
    curl --data-binary @- http://localhost:8080/dataset/ownership/ct/v1/add-objecthash -v
```

Real one:

```bash
echo "{\"timestamp\":\"$(date --iso-8601=seconds)\",\"jurisdiction\":\"NSW\",\"vin\":\"VIN0123456789\"}" | \
    openssl cms -sign -signer certs/NSW.pem -inkey certs/NSW.key -outform DER -stream | \
    curl --data-binary @- https://vin.apps.y.cld.gov.au/dataset/ownership/ct/v1/add-objecthash -v
```

## See data in server

Visit:
<http://localhost:8080/dataset/ownership/>

Or:
<https://vin.apps.y.cld.gov.au/dataset/ownership/>

## Useful commands to test signing / verifying

```bash
echo foo | openssl cms -sign  -signer certs/TAS.pem -inkey certs/TAS.key -outform DER -stream | openssl cms -verify -inform DER -CAfile certs/vinca.pem
```

## Deploy to CloudFoundry

This application can be easily deployed to CloudFoundry and data persisted to a bound Postgres instance:

```bash
# create db
cf create-service postgres shared vin-db

# deploy
mkdir -p deploy
GOOS=linux GOARCH=amd64 go build -o deploy/vin app/main.go
echo "web: ./vin" > deploy/Procfile
cat > deploy/manifest.yml <<EOF
buildpack: binary_buildpack
memory: 350M
disk_quota: 50M
instances: 2
services:
- vin-db
applications:
- name: vin
env:
  VINCA_PEM: |
$(cat certs/vinca.pem | awk '{ print "    " $0 }')
EOF

cf push vin -p deploy/ -f deploy/manifest.yml
```
