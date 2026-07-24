# GitHub Copilot Instructions

This document provides guidance for AI coding agents to effectively contribute to the `in-toto/attestation-verifier` codebase.

## Project Overview & Architecture

This project is a Go-based command-line tool for verifying software supply chain attestations based on an in-toto layout. The layout acts as a policy file, defining expected steps, attestations, and constraints.

The core logic resides in the `verifier` package, with the main entrypoint in `main.go` and command-line handling in `cmd/root.go`.

### Key Concepts & Data Flow

1.  **Layout (`verifier.Layout`)**: A YAML file that defines the supply chain policy. It includes:
    *   `functionaries`: A map of trusted public keys.
    *   `steps`: A list of expected operations in the supply chain (e.g., `clone`, `build`). Each step defines:
        *   `expectedPredicates`: The types of attestations required for the step (e.g., SLSA provenance).
        *   `expectedMaterials`/`expectedProducts`: Rules governing the inputs and outputs of the step.
        *   `expectedAttributes`: CEL expressions to validate against the attestation's predicate.

2.  **Attestations**: DSSE-enveloped in-toto statements (`.json` files) that provide evidence for a supply chain step.

3.  **Verification Process (`verifier.Verify`)**:
    *   The tool is invoked with a layout (`-l`) and a directory of attestations (`-a`).
    *   It loads the layout and all attestations.
    *   It uses the `functionaries` from the layout to verify the signatures on the attestation envelopes.
    *   For each `step` in the layout, it finds the corresponding attestations and verifies them against the step's expectations (`ExpectedPredicates`, artifact rules, and CEL-based attribute rules).

A key file for understanding the core verification logic is `verifier/verifier.go`. The data models for the layout are in `verifier/models.go`.

## Developer Workflow

### Building and Running

The main application can be run directly using `go run`. There are two primary verification commands demonstrated in the repository:

1.  **Simple Verification**: Verifies a set of attestations against a simple layout.
    ```bash
    go run . --layout layouts/layout.yml --attestations-directory test-data
    ```

2.  **Policy Verification (SLSA E2E RFP)**: A SLSA-specific E2E demo that shows how to go from attestations to policies to VSAs.
    See the [`slsa-e2e-rfp/README.md`](slsa-e2e-rfp/README.md) for instructions on how to run this demo.

### Dependencies

Dependencies are managed with Go modules. Key external libraries include:
- `github.com/spf13/cobra`: For the command-line interface.
- `github.com/in-toto/attestation`: For in-toto attestation data structures.
- `github.com/secure-systems-lab/go-securesystemslib`: For DSSE envelope handling and cryptographic verification.
- `github.com/google/cel-go`: For evaluating attribute-matching rules.

To add or update dependencies, edit `go.mod` and run `go mod tidy`.

### Testing

The project currently lacks a formal test suite. When adding new features, also add corresponding unit or integration tests.

## Code Conventions

- The code follows standard Go conventions.
- Logging is done using `github.com/sirupsen/logrus`. Use `log.Info`, `log.Warn`, etc., for structured logging.
- Errors are handled by returning them up the call stack. Avoid `log.Fatal`.
- The `slsa-e2e-rfp` directory contains a separate, more experimental use case. Changes here should be self-contained.
