# emmy - Library for zero-knowledge proofs
Emmy is named after Emmy Noether.

[![Build Status](https://travis-ci.org/xlab-si/emmy.svg?branch=master)](https://travis-ci.org/xlab-si/emmy)

A zero-knowledge proof is protocol by which one party (prover) proves to another party (verifier) that a given statement is true, without conveying any information apart from the fact that the statement is indeed true.

The required properties for zero knowledge proofs are:

 * completeness: if the statement is true, the honest verifier (the verifier that follows the protocol properly) will be convinced of this fact with overwhelming probability
 * soundness: no one who does not know the secret can convince the verifier with non-negligible probability
 * zero knowledge: the proof does not leak any information
 
A good resource on zero-knowledge proofs is [1].

Zero-knowledge proofs can be built upon sigma protocols. Sigma protocols are three-move protocols (commitment, challenge and response) which have the following properties: completeness, special soundness, and special honest zero knowledge verifier (not going into definitions here, see [1]). An example sigma protocol is Schnorr protocol:

![schnorr protocol](https://raw.github.com/xlab-si/emmy/master/img/schnorr_protocol.png)

Here the prover proves that it knows w such that g^w = h mod p (proof of knowledge of a discrete logarithm).

How to make sigma protocols like Schnorr protocol zero-knowledge proofs?

The key is to enforce the verifier to behave honestly. It can be achieved using commitment schemes as depicted below (verifier commits to a challenge and reveals the commited value when sending the challenge to the verifier):

![zero knowledge from sigma](https://raw.github.com/xlab-si/emmy/master/img/zk_from_sigma_protocol.png)

This library aims to provide various proofs (currently supported are listed below) which can be used in scenarios like anonymous digital credentials. Each proof is implemented as sigma protocol which can be turned into zero-knowledge proof and zero-knowledge proof of knowledge using commitments.

For communication between the prover and the verifier gRPC is used. Each sigma protocol contains two message types:

 * ProofRandomData: exchanged in the first step of sigma protocol (based on some randomly generated numbers)
 * ProofData: exchanged in the second step of sigma protocol

To convert sigma protocol into zero-knowledge proof or zero-knowledge proof of knowledge, additional message (OpeningMsg) is exchanged at the beginning. Prover asks for a commitment to a challenge - this makes sigma protocol a zero-knowledge proof. If trapdoor is sent in the last message to the verifier and validated, then we have zero-knowledge proof of knowledge.

# Using emmy

## Installation
```
go install github.com/xlab-si/emmy
```

### Build and run server
```
$ go build -o serve server/*.go
$ ./serve

2017/05/24 12:59:46 12:59:46.967 main ▶ INFO 001 Registering services
2017/05/24 12:59:46 12:59:46.967 NewProtocolServer ▶ INFO 002 Instantiating new protocol server
2017/05/24 12:59:46 12:59:46.967 main ▶ INFO 003 GRPC server listening for connections on port 7007
```

### Build and run client
```
$ go build -o run client/*.go
$ # ./run <example_name> <num_clients> [concurrent]
$ ./run pedersen_ec 100 concurrent  # starts 100 clients concurrently
$ ./run pedersen_ec 100             # starts 100 clients sequentially
```

Supported example names are listed in the tables.

| Sigma protocol | Zero knowledge proof  | Zero knowledge proof of knowledge |
|----------------|-----------------------|-----------------------------------|
| pedersen | pedersen-zkp | pedersen-zkpok |  
| pedersen_ec | pedersen_ec-zkp | pedersen_ec-zkpok |   
| schnorr | schnorr-zkp | schnorr-zkpok |   
| schnorr_ec | schnorr-zkp_ec | schnorr-zkpok_ec | 

| Other |
| ----- |
| dlog_equality |
| dlog_equality_blinded_transcript | 
| pseudonymsys |
| cspaillier |
| split_secret |

For explanations please refer to documentation below.

# Supported schemes

### Discrete logarithm proofs
* **Schnorr protocol: proving knowledge of dlog in multiplicative group of integers modulo p** - Prover wants to prove that it knows *w* such that *g^w = h mod p*.
* **Schnorr protocol: proving knowledge of dlog in elliptic curve group** - Prover wants to prove that it knows *w* such that *g^w = h* in EC group.
* **Chaum-Pedersen protocol** to prove discrete logarithm equality [4]
* **Protocol to prove discrete logarithm equality that produces a blinded transcript** - [5]

### Commitments
* **Pedersen commitment in multiplicative group of integers modulo p**
* **Pedersen commitment in EC group** 

### Pseudonym system [5]

### Verifiable encryption [2]

### Signatures
* **Camenisch-Lysyanskaya signature** - [3]. See test/signatures_test.go.
* **Shamir's secret sharing scheme**

## Roadmap

 * Enable ZKP and ZKPOK for CSPailier 
 * Provide server which will be able to start many verifiers in parallel
 * Support other proofs
 ...


## To compile .proto files

Go into the root project folder and execute:

```
protoc -I comm/pro/ comm/pro/msgs.proto --go_out=plugins=grpc:comm/pro
```

## References

[1] C. Hazay and Y. Lindell. Efficient Secure Two-Party Computation: Techniques and Constructions. Springer, 2010.

[2] J. Camenisch and V. Shoup, Practical verifiable encryption and decryption of discrete logarithms, http://eprint.iacr.org/2002/161, 2002.

[3] J. Camenisch and A. Lysyanskaya. A signature scheme with efficient protocols. In S. Cimato, C. Galdi, and G. Persiano, editors, Security in Communication Networks, Third International Conference, SCN 2002, volume 2576 of LNCS, pages 268–289. Springer Verlag, 2003.

[4] D. Chaum and T. P. Pedersen, Wallet databases with observers, Advances in Cryptology — CRYPTO ’92 (E. F. Brickell, ed.), LNCS, vol. 740, Springer-Verlag, 1993, pp. 89– 105.

[5] A. Lysyanskaya, R. Rivest, A. Sahai, and S. Wolf. Pseudonym systems. In Selected Areas in Cryptography, vol. 1758 of LNCS. Springer Verlag, 1999.