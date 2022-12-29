# ghpub

NodeJS script which sets up a repository with secrets for Scala/Nuget/etc publishing


## Intended use

1. Have Hashicorp Vault address set in `VAULT_ADDR` environment variable with LDAP authentication configured,
2. Run `export VAULT_TOKEN=$(vault login --method=ldap --field token username=$USER)`. If you use other login method, change the command accordingly. If you use LDAP, you may just run `source auth-ldap.sh`.
3. Run `./pub-prepare --owner GITHUBPREFIX --repo GITHUBREPO`

The script expects Vault to have mount `ghpub` configured with versioned v2 KV storage. The mount name can be altered with a command line option (use `--help`)

## Fill the vault

### Automatically

```bash
./pub-prepare --owner 7mind --repo test --writeVault true --readVault false
```

This will read the secrets from terminal and write them into vault.

### Manually

Vault may be provisioned with a script like:

```bash
#!/usr/bin/env bash

set -x
set -e

vault kv put -mount=$VPATH github token=ghp_blah123
vault kv put -mount=$VPATH nuget token=oyblah123
vault kv put -mount=$VPATH sonatype user=7mind password=blah123 email=team@7mind.io
```
