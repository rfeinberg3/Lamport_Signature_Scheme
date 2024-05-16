# Lamport Digital Signature Scheme

This project implements the Lamport Digital Signature Scheme, a method for signing and verifying digital messages using one-time signature keys. The scheme involves three programs: KeyGen, Sign, and Verify.

## Programs

### 1. KeyGen.c

This program generates the secret keys (SK) and public keys (PK) for the Lamport Digital Signature Scheme. It takes a seed file as input and outputs the SK and PK files.

**Compilation**:
gcc KeyGen.c -ltomcrypt -o CertificateAuthority

**Execution**:
./CertificateAuthority Seed1.txt

This will generate the `SK.txt` and `PK.txt` files containing the secret keys and public keys, respectively.

### 2. Sign.c

This program signs a message using the Lamport Digital Signature Scheme. It takes the message file and the SK file as input and outputs the signature file. It also sends the message and signature to Bob (the verifier) using ZeroMQ.

**Compilation**:
gcc Sign.c -ltomcrypt -lzmq -o Alice

**Execution**:
./Alice Message1.txt SK.txt

This will generate the `Signature.txt` file containing the signature and send the message and signature to Bob.

### 3. Verify.c

This program verifies the signature of a message using the Lamport Digital Signature Scheme. It takes the PK file and the message length as input and receives the message and signature from Alice (the signer) using ZeroMQ. It then outputs the verification result to the `Verification.txt` file.

**Compilation**:
gcc Verify.c -ltomcrypt -lzmq -o Bob

**Execution**:
./Bob PK.txt message-length

This will receive the message and signature from Alice, verify the signature using the public keys, and write the verification result to the `Verification.txt` file.

## Dependencies

This project depends on the following libraries:

- LibTomCrypt: A portable, modular, and self-contained cryptographic library
- ZeroMQ: A high-performance asynchronous messaging library

Make sure to have these libraries installed before compiling and running the programs.

## Usage

1. Run the `CertificateAuthority` (KeyGen.c) program to generate the secret keys and public keys.
2. Run the `Alice` (Sign.c) program to sign a message and send it to Bob.
3. Run the `Bob` (Verify.c) program to receive the message and signature from Alice and verify the signature.

The verification result will be written to the `Verification.txt` file.

## Quick Test
Open the `TestVectors` folder in your terminal. Now run:
bash VerifyingYourLamportSolution.sh

## Note

This implementation is for educational purposes only and should not be used in production environments without proper security auditing and consideration of potential vulnerabilities.