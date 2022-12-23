# ghpub

NodeJS script which sets up a repository with secrets for Scala/Nuget/etc publishing

Relies on Hashicorp Vault, requires `VAULT_ADDR` and `VAULT_TOKEN` variables to be set before run.

The vault may be provisioned with a script like:

```bash
#!/usr/bin/env bash

set -x
set -e

export VPATH=secret
export VAULT_ADDR='http://127.0.0.1:8200'

vault secrets enable -path=$VPATH kv || true

vault kv put -mount=$VPATH github token=ghp_blah123
vault kv put -mount=$VPATH nuget token=oyblah123
vault kv put -mount=$VPATH sonatype user=7mind password=blah123 email=team@7mind.io
```
