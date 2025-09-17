# SLSA E2E RFP

## Verify policy

```shell
$ go run slsa-e2e-rfp/commands/verify-policy/*.go
# Warp-generated command to pretty-print the payload inside every attestation JSON file
$ find ./slsa-e2e-rfp/attestations -name "*.json" -exec bash -c 'echo "=== {} ==="; if jq -e ".payload" "{}" > /dev/null 2>&1; then jq -r ".payload" "{}" | base64 -d | jq .; else jq . "{}"; fi; echo' \;
```

## Verify VSA

TODO.