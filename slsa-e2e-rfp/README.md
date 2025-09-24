# SLSA E2E RFP

## Generate and verify Attestations against the Policy

```shell
$ go run slsa-e2e-rfp/commands/verify-policy/*.go

Generating the Source Verification Summary Attestation (VSA)...
Key ID: 937101f8dcc7be06fd1f8c35dbbe9855d784c690e9598a5f11c9b70a0bf46f1f / Public Key: cfec494a7cc842d8340f2c33be5ed55334cba63e5515a8c0f30677211cfaced4
...done.

Generating the Build Provenance Attestation...
Key ID: 8c249ff34cddc2181a14e679577a2acf38216dc01b95be2c218a9faa79c4e2d0 / Public Key: 46a4405f239de13e9db05bdd706ccb329c0b19a9e2880c9e52bfe196641cb876
...done.

Generating the Release Attestation...
Key ID: 0973a4a0155ab13d35e3cfdd3476eaba91044a8693c5aa5e017d97313bd9dc84 / Public Key: 7da885ef5c5cc1255a327fa688474ec9baeb25cfcbb47930361da73e52875cd1
...done.

Verifying Attestations against Policy...
INFO[0000] Verifying layout expiry...                   
INFO[0000] Done.                                        
INFO[0000] Substituting parameters...                   
INFO[0000] Done.                                        
INFO[0000] Fetching verifiers...                        
INFO[0000] Creating verifier for key 8c249ff34cddc2181a14e679577a2acf38216dc01b95be2c218a9faa79c4e2d0 
INFO[0000] Creating verifier for key 0973a4a0155ab13d35e3cfdd3476eaba91044a8693c5aa5e017d97313bd9dc84 
INFO[0000] Creating verifier for key 937101f8dcc7be06fd1f8c35dbbe9855d784c690e9598a5f11c9b70a0bf46f1f 
INFO[0000] Done.                                        
INFO[0000] Loading attestations as claims...            
INFO[0000] Done.                                        
INFO[0000] Verifying claim for step 'source' of type 'https://slsa.dev/verification_summary/v1' by '937101f8dcc7be06fd1f8c35dbbe9855d784c690e9598a5f11c9b70a0bf46f1f'... 
INFO[0000] Applying material rules...                   
INFO[0000] Evaluating rule `DISALLOW *`...              
INFO[0000] Applying product rules...                    
INFO[0000] Evaluating rule `CREATE https://github.com/sigstore/sigstore-js/*`... 
INFO[0000] Evaluating rule `DISALLOW *`...              
INFO[0000] Applying attribute rules...                  
INFO[0000] Evaluating rule `predicate.verifier.id == 'https://github.com/gittuf/gittuf'`... 
INFO[0000] Done.                                        
INFO[0000] Verifying claim for step 'build' of type 'https://slsa.dev/provenance/v1' by '8c249ff34cddc2181a14e679577a2acf38216dc01b95be2c218a9faa79c4e2d0'... 
INFO[0000] Applying material rules...                   
INFO[0000] Evaluating rule `MATCH https://github.com/sigstore/sigstore-js/* IN git+ WITH PRODUCTS FROM source`... 
INFO[0000] Evaluating rule `DISALLOW *`...              
INFO[0000] Applying product rules...                    
INFO[0000] Evaluating rule `CREATE sigstore-3.0.0.tgz`... 
INFO[0000] Evaluating rule `DISALLOW *`...              
INFO[0000] Applying attribute rules...                  
INFO[0000] Evaluating rule `predicate.buildDefinition.buildType == 'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1'`... 
INFO[0000] Done.                                        
INFO[0000] Verifying claim for step 'release' of type 'https://in-toto.io/attestation/release/v0.1' by '0973a4a0155ab13d35e3cfdd3476eaba91044a8693c5aa5e017d97313bd9dc84'... 
INFO[0000] Applying material rules...                   
INFO[0000] Evaluating rule `MATCH * WITH PRODUCTS FROM build`... 
INFO[0000] Evaluating rule `DISALLOW *`...              
INFO[0000] Applying product rules...                    
INFO[0000] Applying attribute rules...                  
INFO[0000] Done.                                        
INFO[0000] Verification successful!                     
...done.

Generating the Policy VSA...
Key ID: 64b5e39bbf527b383a758f40501005c470df4d5463c3183486da1a04a0cce755 / Public Key: 1f81c9eedcb9325243706a10cd24cf672e5b6f31cd419a4976ea7b6c166181f9
...done.
```

## Pretty-print payload inside every Attestation JSON file

```shell
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

## Verify the Artifact against the Policy VSA

```shell
$ go run slsa-e2e-rfp/commands/verify-vsa/main.go

Policy VSA verified by key 64b5e39bbf527b383a758f40501005c470df4d5463c3183486da1a04a0cce755
Artifact hash 3c73227e187710de25a0c7070b3ea5deffe5bb3813df36bef5ff2cb9b1a078c3636c98f31f8223fd8a17dc6beefa46a8b894489557531c70911000d87fe66d78 verified against the Policy VSA subject
Policy VSA verification PASSED
Policy VSA is less than a day old
```
