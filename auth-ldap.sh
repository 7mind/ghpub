#!/usr/bin/env bash

is_sourced() {
    if [ -n "$ZSH_VERSION" ]; then
        case $ZSH_EVAL_CONTEXT in *:file:*) return 0 ;; esac
    else # Add additional POSIX-compatible shell names here, if needed.
        case ${0##*/} in dash | -dash | bash | -bash | ksh | -ksh | sh | -sh) return 0 ;; esac
    fi
    return 1
}

is_sourced && SOURCED=1 || SOURCED=0

if [[ SOURCED == "0" ]]; then
    echo "This script intended to be sourced"
else
    echo "Ok, the script is sourced"
fi

if [[ -v VAULT_ADDR ]]; then
    echo "Going to get a token for $VAULT_ADDR as $USER"
    export VAULT_TOKEN=$(vault login --method=ldap --field token username=$USER)
    echo "You may update the environment with:"
    echo "  export VAULT_TOKEN=$VAULT_TOKEN"
else
    echo "VAULT_ADDR is unset"
fi
