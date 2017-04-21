# emmy

Library for zero-knowledge proofs. 

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

### Verifiable encryption [2]

For an example run:

```
emmy -example=cspaillier -client=false
emmy -example=cspaillier -client=true
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
