# in-toto-attestation-verifier

This is a prototype of verification capabilities introduced in in-toto
enhancements [10](https://github.com/in-toto/ITE/pull/49) and
[11](https://github.com/in-toto/ITE/pull/50).

## Usage

Install using `go install`. Assuming `$GOPATH/bin` is in your path, you should
be able to invoke the verifier using `in-toto-attestation-verifier`.

## Example

```bash
$ in-toto-attestation-verifier -l layout-steps.yml -a test-data
INFO[0000] Verifying expiry...
INFO[0000] Done.
INFO[0000] Fetching verifiers...
INFO[0000] Creating verifier for key fe1c6281c5ff13e35286cc67e5a1fb3e6575b840a6c39ca4267d3805eb17288a
INFO[0000] Done.
INFO[0000] Loading attestations as claims...
INFO[0000] Done.
INFO[0000] Verifying claim for step clone of type https://in-toto.io/attestation/link/v0.3 by fe1c6281c5ff13e35286cc67e5a1fb3e6575b840a6c39ca4267d3805eb17288a
INFO[0000] Evaluating rule size(command) == 0
INFO[0000] Verifying claim for step test of type https://in-toto.io/attestation/test-result/v0.1 by fe1c6281c5ff13e35286cc67e5a1fb3e6575b840a6c39ca4267d3805eb17288a
INFO[0000] Evaluating rule size(failedTests) == 0
INFO[0000] Evaluating rule result == 'PASSED'
```
