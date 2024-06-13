# Deployment of IBM SE verifier

## Generate EC keys
```
openssl genrsa -aes256 -passout pass:test1234 -out encrypt_key-psw.pem 4096
openssl rsa -in encrypt_key-psw.pem -passin pass:test1234 -pubout -out encrypt_key.pub
openssl rsa -in encrypt_key-psw.pem -out encrypt_key.pem
```


## Download Certs, CRLs, Root CA
https://www.ibm.com/support/resourcelink/api/content/public/secure-execution-gen2.html

### Certs
ibm-z-host-key-signing-gen2.crt

### CRL
ibm-z-host-key-gen2.crl (1KB)

### Root CA
DigiCertCA.crt 

## Download HKD
https://www.ibm.com/docs/en/linux-on-z?topic=execution-verify-host-key-document

## Get SE Header
https://github.com/ibm-s390-linux/s390-tools/blob/v2.33.1/rust/pvattest/tools/pvextract-hdr
```
./pvextract-hdr -o hdr.bin se.img
```

## Generate KBS key
```
openssl genpkey -algorithm ed25519 > kbs.key
openssl pkey -in kbs.key -pubout -out kbs.pem
```
## Build KBS
```
cargo install --locked --path kbs/src/kbs --no-default-features --features coco-as-builtin,openssl,resource,opa 
```
## Launch KBS as a program
```
./start-kbs.sh
```

## Launch KBS with mount via docker-compose

- Start
```
cd ../test_data/se/
docker-compose up -d
```

- Logs or shutdown
```
cd ../test_data/se/
docker-compose logs web
docker-compose down
```

## Expose the KBS endpoint

