After running `make examples`, if SSL is enabled, you can quickly test HTTPS, with optional client-based certificate authentication using the following process within the build directory:

```
# do all the stupid ssl generation
./examples/https/bin/generate.sh

# Test without client auth

# Run the server
./examples/example_https              \
  -cert examples/https/server-crt.pem \
  -key  examples/https/server-key.pem

# Make a request
curl -vk https://localhost:4443/

# Test WITH client auth

./examples/example_https              \
  -cert examples/https/server-crt.pem \
  -key  examples/https/server-key.pem \
  -ca   examples/https/ca-crt.pem     \
  -verify-peer                        \
  -verify-depth 2                     \
  -enforce-peer-cert

# Make a request with the client key
curl -kv \
  --key  examples/https/client1-key.pem \
  --cert examples/https/client1-crt.pem \
  https://localhost:4443/
```
