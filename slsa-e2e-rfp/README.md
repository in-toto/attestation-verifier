# SLSA E2E RFP

## Verify policy

```shell
$ go run slsa-e2e-rfp/commands/verify-policy/*.go
# Warp-generated command to pretty-print the payload inside every attestation JSON file
$ find ./slsa-e2e-rfp/attestations -name "*.json" -exec bash -c 'echo "=== {} ==="; if jq -e ".payload" "{}" > /dev/null 2>&1; then jq -r ".payload" "{}" | base64 -d | jq .; else jq . "{}"; fi; echo' \;
```

### source.937101f8.json

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "uri": "https://github.com/sigstore/sigstore-js/commit/3a57a741bfb9f7c3bca69b63e170fc28e9432e69",
      "digest": {
        "gitCommit": "3a57a741bfb9f7c3bca69b63e170fc28e9432e69"
      },
      "annotations": {
        "source_refs": [
          "refs/heads/main",
          "refs/heads/release_1.0"
        ]
      }
    }
  ],
  "predicateType": "https://slsa.dev/verification_summary/v1",
  "predicate": {
    "policy": {
      "uri": "https://example.com/slsa_source.policy"
    },
    "resourceUri": "git+https://github.com/sigstore/sigstore-js",
    "timeVerified": "1985-04-12T23:20:50.520Z",
    "verificationResult": "PASSED",
    "verifiedLevels": [
      "SLSA_SOURCE_LEVEL_3"
    ],
    "verifier": {
      "id": "https://github.com/gittuf/gittuf"
    }
  }
}
```

### build.8c249ff3.json

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "pkg:npm/sigstore@3.0.0",
      "digest": {
        "sha512": "3c73227e187710de25a0c7070b3ea5deffe5bb3813df36bef5ff2cb9b1a078c3636c98f31f8223fd8a17dc6beefa46a8b894489557531c70911000d87fe66d78"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
      "externalParameters": {
        "workflow": {
          "path": ".github/workflows/release.yml",
          "ref": "refs/heads/main",
          "repository": "https://github.com/sigstore/sigstore-js"
        }
      },
      "internalParameters": {
        "github": {
          "event_name": "push",
          "repository_id": "495574555",
          "repository_owner_id": "71096353"
        }
      },
      "resolvedDependencies": [
        {
          "digest": {
            "gitCommit": "3a57a741bfb9f7c3bca69b63e170fc28e9432e69"
          },
          "uri": "git+https://github.com/sigstore/sigstore-js/commit/3a57a741bfb9f7c3bca69b63e170fc28e9432e69"
        }
      ]
    },
    "runDetails": {
      "builder": {
        "id": "https://github.com/actions/runner/github-hosted"
      },
      "metadata": {
        "invocationId": "https://github.com/sigstore/sigstore-js/actions/runs/11331290387/attempts/1"
      }
    }
  }
}
```

### release.0973a4a0.json

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "pkg:npm/sigstore@3.0.0",
      "digest": {
        "sha512": "3c73227e187710de25a0c7070b3ea5deffe5bb3813df36bef5ff2cb9b1a078c3636c98f31f8223fd8a17dc6beefa46a8b894489557531c70911000d87fe66d78"
      }
    }
  ],
  "predicateType": "https://in-toto.io/attestation/release/v0.1",
  "predicate": {
    "releaseId": "1234567890"
  }
}
```

## Verify VSA

TODO.