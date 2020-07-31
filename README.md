# Password-authenticated Decentralized Identities (PDIDs)

PDIDs are human-meaningful, globally unique, and decentralized identities,
which are securely authenticated with passwords.  The technical details of PDIDs
are presented in 
[*P.Szalachowski, "Password-authenticated Decentralized Identities", 2020*]()

This repository contains a proof-of-concept PDIDs implementation, intended **for demonstration purposes only**.


### Code

- `lib/` contains main PDID procedures including the implementation of
  modified [OPAQUE](https://eprint.iacr.org/2018/163.pdf) and [HMQV](https://eprint.iacr.org/2005/176.pdf) protocols
- `lib/ecc.{c,h}` are from [Easy-ECC](https://github.com/esxgx/easy-ecc). It is
  modified (to be compatible with Intel SGX and its SDK) and extended by
PDID-related functions (prefixed with `pdid_`) 
- `lib/tweetnacl.{c,h}` are from [TweetNaCl](https://tweetnacl.cr.yp.to/) 
- `chaincode/` is the GPM smart contract to be deployed with [Hyperledger Fabric Private Chaincode](https://github.com/hyperledger-labs/fabric-private-chaincode) (FPC)
- `fpc-1.0-gitdiff.patch` is fix for building FPCv1.0 and adding an SGX's ocall getting local system time (used for performance measurements only)


### Local tests
Local (emulation) test should work out of box: `make && ./local_test`
For better performance, you can use [NaCl](https://nacl.cr.yp.to/) instead of TweetNaCl. Install NaCl, change the build path to yours
`export NACL_PATH=../../nacl-20110221/build/Latitude5280`
and compile with the following flags (for x86_64)
`-I${NACL_PATH}/include/amd64 -L${NACL_PATH}/lib/amd64 -lnacl -DWITH_NACL`

The integration test requires FPC deployment.


### Hyperledger deployment

1) Generate `./integration_test` by `make`
1) Install FPC as described [here](https://github.com/hyperledger-labs/fabric-private-chaincode)
(I used the concept release 1.0 [branch](https://github.com/hyperledger-labs/fabric-private-chaincode/tree/concept-release-1.0).)
2) Do a clean FPC build (even if you go with the Docker option) and before building apply the patch from this directory:
`git apply fpc-1.0-gitdiff.patch`
3) Copy `chaincode/` and `lib/` to FPC's `examples/`. Then `cd examples/chaincode && make`.
4) In another terminal, run `./integration_test` and follow its instructions 


### Caveats and TODO

- If you get *"Enclave: VIOLATION!!! Oh oh! cmac does not match!"* in FPC logs, see my comment in `lib/pdid_gpm.c:11`
- Sanity checks and inline TODO/FIXMEs
- Constant-time `gpm_auth()` and optimized server/client-side cryptographic operations
- Fixing compilation warnings and C/C++ mixes
- At least in FPCv1.0, state keys are not encrypted, revealing registered
  usernames. An easy fix is to generate a secret upon contract creation, and
use `PRF(secret|username)` as state keys, instead of plain usernames.
- ...

### Author

[Pawel Szalachowski](https://pszal.github.io)
