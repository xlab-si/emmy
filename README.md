# emmy (after Emmy Noether)

Library for zero-knowledge proofs. 

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


## Currently supported schemes

### Discrete logarithm proofs

#### Schnorr protocol (proving knowledge of dlog) in multiplicative group of integers modulo p

Prover wants to prove that it knows w such that g^w = h mod p.

To run an example of a proof, run a server (see cli.go):

```
emmy -example=schnorr -client=false
```

Run client:

```
emmy -example=schnorr -client=true
```

The two commands above executed a sigma protocol to prove a knowledge of dlog in multiplicative group of integers.

To run zero-knowledge proof, run:
```
emmy -example=schnorr_zkp -client=false
emmy -example=schnorr_zkp -client=true
```
To run zero-knowledge proof of knowledge, run:
```
emmy -example=schnorr_zkpok -client=false
emmy -example=schnorr_zkpok -client=true
```
#### Schnorr protocol (proving knowledge of dlog) in elliptic curve group

Prover wants to prove that it knows w such that g^w = h in EC group.

To run an example of a proof, run a server:

```
emmy -example=schnorr_ec -client=false
```

Run client:

```
emmy -example=schnorr_ec -client=true
```

The two commands above executed a sigma protocol to prove a knowledge of dlog in EC group.

To run zero-knowledge proof, run:
```
emmy -example=schnorr_ec_zkp -client=false
emmy -example=schnorr_ec_zkp -client=true
```
To run zero-knowledge proof of knowledge, run:
```
emmy -example=schnorr_ec_zkpok -client=false
emmy -example=schnorr_ec_zkpok -client=true
```

#### Chaum-Pedersen protocol [4] to prove discrete logarithm equality

```
emmy -example=dlog_equality
```

#### Protocol to prove discrete logarithm equality that produces a blinded transcript [5]

```
emmy -example=dlog_equality_blinded_transcript
```

### Commitments

#### Pedersen commitment in multiplicative group of integers modulo p

For an example run:

```
emmy -example=pedersen -client=false
emmy -example=pedersen -client=true
```

#### Pedersen commitment in EC group

For an example run:

```
emmy -example=pedersen_ec -client=false
emmy -example=pedersen_ec -client=true
```

### Pseudonym system [5]

```
emmy -example=pseudonymsys
```

### Verifiable encryption [2]

For an example run:

```
emmy -example=cspaillier -client=false
```

### Signatures

#### Camenisch-Lysyanskaya signature [3]

See test/signatures_test.go.

### Shamir's secret sharing scheme

To run an example:

```
emmy -example=split_secret -client=false
```

## Todo

 * Enable ZKP and ZKPOK for CSPailier 
 * Provide server which will be able to start many verifiers in parallel
 * Support other proofs
 ...

## Installation

```
go install github.com/xlab-si/emmy
```

## To compile .proto files

Go into the root project folder and execute:

```
protoc -I comm/pro/ comm/pro/msgs.proto --go_out=plugins=grpc:comm/pro

```

[1] C. Hazay and Y. Lindell. Efficient Secure Two-Party Computation: Techniques and Constructions. Springer, 2010.

[2] J. Camenisch and V. Shoup, Practical verifiable encryption and decryption of discrete logarithms, http://eprint.iacr.org/2002/161, 2002.

[3] J. Camenisch and A. Lysyanskaya. A signature scheme with efficient protocols. In S. Cimato, C. Galdi, and G. Persiano, editors, Security in Communication Networks, Third International Conference, SCN 2002, volume 2576 of LNCS, pages 268–289. Springer Verlag, 2003.

# Build and run server

```
$ go build -o serve server/*.go
$ ./serve

2017/05/24 12:59:46 12:59:46.967 main ▶ INFO 001 Registering services
2017/05/24 12:59:46 12:59:46.967 NewProtocolServer ▶ INFO 002 Instantiating new protocol server
2017/05/24 12:59:46 12:59:46.967 main ▶ INFO 003 GRPC server listening for connections on port 7007
```

# Build and run client
```
$ go build -o run client/*.go
$ # ./run <example_name> <num_clients> [concurrent]
$ ./run pedersen_ec 100 concurrent  # starts 100 clients concurrently
$ ./run pedersen_ec 100             # starts 100 clients sequentially
```

[4] D. Chaum and T. P. Pedersen, Wallet databases with observers, Advances in Cryptology — CRYPTO ’92 (E. F. Brickell, ed.), LNCS, vol. 740, Springer-Verlag, 1993, pp. 89– 105.

[5] A. Lysyanskaya, R. Rivest, A. Sahai, and S. Wolf. Pseudonym systems. In Selected Areas in Cryptography, vol. 1758 of LNCS. Springer Verlag, 1999.