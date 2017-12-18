After running `make examples`, if SSL is enabled, you can quickly test HTTPS, with optional client-based certificate authentication using the following process within the build directory:

```
# do all the stupid ssl generation
./examples/https/bin/generate.sh

# Test without client auth

# Run the server
./examples/example_https_server       \
  -cert examples/https/server-crt.pem \
  -key  examples/https/server-key.pem \
  -verify-client off

# Make a request
curl -vk https://localhost:4443/

# Test WITH client auth

./examples/example_https_server       \
  -cert examples/https/server-crt.pem \
  -key  examples/https/server-key.pem \
  -ca   examples/https/ca-crt.pem     \
  -verify-client on                   \
  -verify-depth  2

# Make a request with the client key
curl -kv \
  --key  examples/https/client1-key.pem \
  --cert examples/https/client1-crt.pem \
  https://localhost:4443/
```

The output (with client-certs) should look like:

```
< HTTP/1.1 200 OK
< X-SSL-Subject: /C=US/ST=MA/L=Boston/O=Critical Stack/OU=evhtp/CN=client1/emailAddress=nate@cl0d.com
< X-SSL-Issuer: /C=US/ST=MA/L=Boston/O=Critical Stack/OU=evhtp/CN=ca/emailAddress=nate@cl0d.com
< X-SSL-Notbefore: Dec  7 16:10:34 2017 GMT
< X-SSL-Notafter: Sep  1 16:10:34 2020 GMT
< X-SSL-Serial: 57459A54BD08848C6D1546C2733EAD8A03553670
< X-SSL-Cipher: ECDHE-RSA-AES256-GCM-SHA384
< X-SSL-Sha1: 7A:68:47:CD:79:18:FF:DA:65:BC:67:6B:C2:5D:F3:66:9A:4A:64:7A
< X-SSL-Certificate: -----BEGIN CERTIFICATE-----
< 	MIIFkDCCA3igAwIBAgIUV0WaVL0IhIxtFUbCcz6tigNVNnAwDQYJKoZIhvcNAQEL
< 	BQAwfzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1BMQ8wDQYDVQQHDAZCb3N0b24x
< 	FzAVBgNVBAoMDkNyaXRpY2FsIFN0YWNrMQ4wDAYDVQQLDAVldmh0cDELMAkGA1UE
< 	AwwCY2ExHDAaBgkqhkiG9w0BCQEWDW5hdGVAY2wwZC5jb20wHhcNMTcxMjA3MTYx
< 	MDM0WhcNMjAwOTAxMTYxMDM0WjCBhDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1B
< 	MQ8wDQYDVQQHDAZCb3N0b24xFzAVBgNVBAoMDkNyaXRpY2FsIFN0YWNrMQ4wDAYD
< 	VQQLDAVldmh0cDEQMA4GA1UEAwwHY2xpZW50MTEcMBoGCSqGSIb3DQEJARYNbmF0
< 	ZUBjbDBkLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALVoTyUm
< 	62PqJ9RHkNewV+0Dn6AvTVYXQRIejORB75e1OklAp3LGw+Nlc1iP5/MjKzTtMpxk
< 	kLDTDDhiX1mC2j9BDYOC6gpWEVosyU+fXaQvCxWKy4BASPUk7toLwgHxv855TTjV
< 	2pe6VtAsImCT6sUGrKDnywAFvsBriXnzbTllm4gl7oPi8TrVZhk475JjEKgGKzsS
< 	wtpbxNUqiTXe5lQ/jU6oCCMWG1VWgPLLTIZElhp/TPqLO976DutPXuCBy56NoPMy
< 	DRm7YarhmG1vQNFdeJmC8/xdnKCbQpVhR9sF13tNIc+9QlTKNwzn375MK9e+xjXO
< 	nc8RuqRLeJcMrs5bx5Mtd28F+yNA0riGGtp72vse95bG0PoVUhAqzog4iceHtt6M
< 	4jyyBhICHYKhkrAYoy3lQdfckiiu5GjZ4rPAq+PP4XPgcXYeqxph6OA+IJwUcWjK
< 	KjfQHvKJbIfo1ILQ4wzGxJ2KAE7F8CBrgokhYmshOMpDx6C4RPwifbtN2GcJN3Vc
< 	kaKGwE72PExFcCLKXwJvXTz+4P87JywCCtYXbUXlgn6rMe4JSRn1NZF00nkeV5bD
< 	AwCCoqSR5Qg9VUyhZKMF3zyQjHKS07SRDyl2vKLFUxnIu+6y4FxvnQqQOdDoz0BG
< 	Uf/s2KNRWK3w3i7hDz0mAQpXyeqmGilT4NZhAgMBAAEwDQYJKoZIhvcNAQELBQAD
< 	ggIBAIypf+0b+5xDRZ4IkcnlbUemZ0xt14UIw4N1Dr2kqp94gu4Z1nkLvYpLg61W
< 	sy3vJLDKc1kSPZG5sPEj/W9zophaSQzL8P/yLHQ3psk2+ie/XDmpmvMsvsVExgut
< 	lOExwMVfp+dIJ1cVfK5i8oMIE0IBbtdAIE/tzV+zzHpvAdA9KDcydW4oF+FLRLmQ
< 	+qfKnK1BkxWqQayNmsbVN63ao8i/4OKD5VtKGPC5RdsEURIDc579lFKACpUnQGaJ
< 	EKX/dKNiqoJSqOEDSsCN6jSJ7uTr5do+7xydqOcTQ+gI3FQsC1NjseqRRU0Q4HVL
< 	95crEmqxlOxOjcrQK6U36HyKfn7EJ1B6/SJM8U9abOKBRUQjgLlrC6GaA/rToHmX
< 	mlkqw2nKTnZhvIGmi0UjwtOD8rQnGahnq+jwoQV6Ag2YbSfeygvajJvdLBjEBYm+
< 	5F6nQgv3JR9iJoS9AxcCEURH7jIAfdbYT6RBT3VARZyPcPtLSMFLLcXh0Z/Egifi
< 	f+xTIL7mCgdW2Jp5s8cNjhrWk6dJVaXwwA6MNSfDeWeu7uHRm3Ir0Jwoe5I2pENm
< 	mKueI6EhIKc6tdQWS6t+ZM0IJsVvhh4s0FqeUFYCP7RxG+P4u5wZxHdjbfUUJ8zA
< 	xHMrDvO8p6dwRUDAPkOqCPpdGmBky/ukBXNi2u0OOJ+wUgoA
< 	-----END CERTIFICATE-----
< Content-Length: 0
< Content-Type: text/plain
<

```
