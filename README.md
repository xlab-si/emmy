# emmy - Library for zero-knowledge proofs [![Build Status](https://travis-ci.org/xlab-si/emmy.svg?branch=master)](https://travis-ci.org/xlab-si/emmy)

#### What is a Zero-Knowlede proof (ZKP)?
A zero-knowledge proof is protocol by which one party (prover) proves to another party (verifier) that a given statement is true, without conveying any information apart from the fact that the statement is indeed true.

The required properties for zero knowledge proofs are:

 * _completeness_ - if the statement is true, the honest verifier (the verifier that follows the protocol properly) will be convinced of this fact with overwhelming probability,
 * _soundness_ - no one who does not know the secret can convince the verifier with non-negligible probability,
 * _zero knowledge_ - the proof does not leak any information.
 
A good resource on zero-knowledge proofs is [1].

#### How can we build Zero-Knowledge proofs?
Zero-knowledge proofs can be built upon **sigma protocols**. Sigma protocols are three-move protocols (commitment, challenge and response) which have the following properties: _completeness_, _special soundness_, and _special honest zero knowledge verifier_ (not going into definitions here, please refer to [1]). An example of a 
sigma protocol is Schnorr protocol, where the prover proves that he knows *w* such that *g^w = h mod p* (proof of knowledge of a discrete logarithm):

![schnorr protocol](https://raw.github.com/xlab-si/emmy/master/img/schnorr_protocol.png)

In the first step of the sigma protocol, a pair of messages for proving the knowledge of random data (e.g. based on a large random number) is exchanged. In the second step of the protocol, the prover and the verifier exchange a pair of messages proving the knowledge of the actual data.

We can turn sigma protocols like Schnorr protocol into **zero-knowledge proofs (ZKP)** or **zero-knowledge proof of knowledge (ZKPOK)**. The key is to enforce the verifier to behave honestly. This can be achieved using **commitment schemes**, where the verifier commits to a challenge and reveals the commited value when sending the challenge to the prover, for instance, like depicted below:
![zero knowledge from sigma](https://raw.github.com/xlab-si/emmy/master/img/zk_from_sigma_protocol.png)

We can see that the prover asks for a commitment to a challenge (therefore an additional message exchanged is at the beginning). We now have a zero-knowledge proof. Furthermore, if the prover sends a trapdoor to the verifier in the last message of the protocol, and the verifier is able to validate it, then we have zero-knowledge proof of knowledge.

#### What does emmy offer?
Emmy is a library that provides various proofs which can be used in scenarios like *anonymous digital credentials*. Each proof is implemented as a sigma protocol which can be turned into a zero-knowledge proof (ZKP) or a zero-knowledge proof of knowledge (ZKPOK) using commitment schemes.

For communication between the prover and the verifier *emmy* uses [Protobuffers](https://developers.google.com/protocol-buffers/) and [gRPC](http://www.grpc.io/). In terms of communication, the prover takes on the role of client, and the verifier takes on the role of server. Emmy offers a server capable of serving (verifying) several clients (provers) concurrently. 

#### What does emmy stand for?
Emmy is named after [Emmy Noether](https://sl.wikipedia.org/wiki/Emmy_Noether).

# Using emmy

## Installation
```
go install github.com/xlab-si/emmy
```

### Running examples
If you want to see any of the protocols supported by emmy in action, take a look at _examples.go_. There, we first spin up a GRPC server and afterwards run the desired number of clients (either sequentially or concurrently) for the chosen protocol. You can specify:

1. Which protocol to run,
2. How many clients to start,
3. How to run the clients (sequentially or concurrently).

This is the expected format:
```
$ emmy <example_name> <num_clients> [concurrent]
```

If you want to run the clients sequentially (e.g. for benchmarking purposes), just omit the "concurrent" option.

Here's an example: 

```
$ emmy pedersen_ec 100 concurrent  # starts 100 clients concurrently
$ emmy pedersen_ec 100             # starts 100 clients sequentially
```

Currently supported examples with fully implemented communication layer (e.g. client-server communication via RPCs) are listed in the tables below. Note that the ones not ticked are also implemented, but not from communication perspective.

| Sigma protocol | Zero knowledge proof  | Zero knowledge proof of knowledge |
|----------------|-----------------------|-----------------------------------|
| [✓] pedersen | [✗] pedersen-zkp | [✗] pedersen-zkpok |  
| [✓] pedersen_ec | [✗] pedersen_ec-zkp | [✗] pedersen_ec-zkpok |   
| [✓] schnorr | [✓] schnorr-zkp | [✓] schnorr-zkpok |   
| [✓] schnorr_ec | [✓] schnorr-zkp_ec | [✓] schnorr-zkpok_ec | 

| Other |
| ----- |
| [✗] dlog_equality |
| [✗] dlog_equality_blinded_transcript | 
| [✗] pseudonymsys |
| [✗] cspaillier |
| [✗] cspaillier_ec |
| [✗] split_secret |

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

# Roadmap
* Enable ZKP & ZKPOK for CSPailier and Pedersen 
* Implement communication layer for latest protocols
* Reorganize library - divide client, server, core (to be decided)
* Benchmarks
* ...

### To compile .proto files

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