# SLSA E2E RFP

## Verify policy

```shell
$ go run slsa-e2e-rfp/commands/verify-policy/*.go
# Pretty-print payload inside every Attestation JSON file
$ find ./slsa-e2e-rfp/attestations -name "*.json" -exec bash -c 'echo "=== {} ==="; jq -r ".payload" "{}" | base64 -d | jq .; echo' \;
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

### policy.64b5e39b.json

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
  "predicateType": "https://slsa.dev/verification_summary/v1",
  "predicate": {
    "inputAttestations": [
      {
        "digest": {
          "sha2-256": "1cc9c70f6080b3b5cf09092302301c46852c66c7e1a6d42f840e9809b7975aaa"
        },
        "uri": "slsa-e2e-rfp/attestations/build.8c249ff3.json"
      },
      {
        "digest": {
          "sha2-256": "432046ba94d9d86415fa079a0a120aedb4147c75d027c9799f814feeddaf311c"
        },
        "uri": "slsa-e2e-rfp/attestations/release.0973a4a0.json"
      },
      {
        "digest": {
          "sha2-256": "e5585d627a08a6eedd384a4ce799a42e3e9518c8860d738621eaaf5273d67d15"
        },
        "uri": "slsa-e2e-rfp/attestations/source.937101f8.json"
      },
      {
        "digest": {
          "sha2-256": "23d65aaf63e5e79440fbdb25e0145f4629778b397e13f6a5c3bce6a8adf074bc"
        },
        "uri": "slsa-e2e-rfp/parameters/source-build-release.json"
      }
    ],
    "policy": {
      "digest": {
        "sha2-256": "373c216d5fe49a0177660152824b0b0e3de87ea292522221cfa088c8dbef5579"
      },
      "uri": "slsa-e2e-rfp/policies/source-build-release.yaml"
    },
    "timeVerified": "2025-09-23T08:16:36.374263393Z",
    "verificationResult": "PASSED",
    "verifiedLevels": [
      "SLSA_BUILD_LEVEL_3"
    ],
    "verifier": {
      "id": "https://github.com/in-toto/attestation-verifier"
    }
  }
}
```

## Verify VSA

```shell
$ go run slsa-e2e-rfp/commands/verify-vsa/main.go

Policy VSA verified by key 64b5e39bbf527b383a758f40501005c470df4d5463c3183486da1a04a0cce755
Artifact hash 3c73227e187710de25a0c7070b3ea5deffe5bb3813df36bef5ff2cb9b1a078c3636c98f31f8223fd8a17dc6beefa46a8b894489557531c70911000d87fe66d78 verified against the Policy VSA subject
Policy VSA verification PASSED
Policy VSA is less than a day old
```
