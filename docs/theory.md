# A quick review of the theory behind emmy

## What is a zero-knowlede proof (ZKP)?

A zero-knowledge proof is protocol by which one party (prover) proves to another party (verifier) that a given statement is true, without conveying any information apart from the fact that the statement is indeed true.

The required properties for zero knowledge proofs are:

- _completeness_ - if the statement is true, the honest verifier (the verifier that follows the
  protocol properly) will be convinced of this fact with overwhelming probability,
- _soundness_ - no one who does not know the secret can convince the verifier with non-negligible
  probability,
- _zero knowledge_ - the proof does not leak any information.

A good resource on zero-knowledge proofs is [1].

## How can we build zero-knowledge proofs?

Zero-knowledge proofs can be built upon **sigma protocols**. Sigma protocols are three-move protocols
(commitment, challenge and response) which have the following properties: _completeness_, _special soundness_, and _special honest zero knowledge verifier_ (not going into definitions here, please refer to [1]). An example of a sigma protocol is Schnorr protocol, where the prover proves that he knows $w$ such that $g^w \equiv h \pmod p$ (proof of knowledge of a discrete logarithm):

![schnorr protocol](./img/schnorr_protocol.png)

We can turn sigma protocols like Schnorr protocol into **zero-knowledge proofs (ZKP)**. The key is to enforce the verifier to behave honestly. This can be achieved by using **commitment scheme** [2] or by using one-bit challenges. Both techniques will be described below.

How a Schnorr protocol cam be executed in emmy, i.e. given $g, t, p$ how to prove the knowledge of $s$ where $t \equiv g^s \pmod p$:

```go
prover := schnorr.NewProver(group, types.Sigma)
verifier := schnorr.NewVerifier(group, types.Sigma)

x := prover.GetProofRandomData(s, g)
verifier.SetProofRandomData(x, g, t)

challenge, _ := verifier.GetChallenge()
z, _ := prover.GetProofData(challenge)
verified := verifier.Verify(z, nil)
```

The second parameter in both constructors specifies whether sigma protocol or ZKP should be executed
(ZKP is sigma protocol extended with commitment scheme to enforce the verifier to behave honestly).

Note that emmy provides a communication layer which enables execution of the protocols on two
remote devices. For brevity the examples here assume the execution of prover and verifier
on the same device.

### How can we prove that a protocol is sound

That means - how can a prover prove the knowledge of a secret. This is done by showing that there exists an algorithm which can extract the knowledge of a secret if the prover is used as a black-box and can be rewinded to output the same first message in two protocol executions.

Thus, in Schnorr protocol the transcripts of two protocol executions are $x \equiv g^r \pmod p, c_1, z_1$ and
$x \equiv g^r \pmod p, c_2, z_2$. The parameters $g, h, p$ are publicly known. Prover is proving the knowledge of $s$ such that:

$$
g^s \equiv t \pmod p
$$

In the last step of both executions the extractor (playing the role of the verifier) verified that:

$$
g^{z_1} = g^r \times (g^s)^{c_1} = g^r \times t^{c_1} \pmod p
$$

$$
g^{z_2} = g^r \times (g^s)^{c_2} = g^r \times t^{c_2} \pmod p
$$

Extractor divides both equations:

$$
g^{z_2-z_1} = t^{c_2-c_1} \pmod p
$$

Note that this is in Schnorr group which is cyclic with order $q$ (see crypto/groups package).

$$
g^{z_2-z_1} = (g^s)^{c_2-c_1} = g^{s\times(c_2-c_1)} \pmod p
$$

Because Schnorr group is cyclic and its order is $q$:

$$
z_2-z_1 \equiv s \times (c_2-c_1) \pmod q
$$

Thus the extractor can compute s by computing inverse of $c_2-c_1$ modulo $q$:

$$
s \equiv (z_2-z_1) \times (c_2-c_1)_\text{inv} \pmod q
$$

Note that this extractor works only if the order of the groups is known ($q$ in Schnorr).

The extractor can work for groups with hidden order if $c_2-c_1$ divides $z_2-z_1$ which is the case in Damgard-Fujisaki commitment scheme [3] or if one-bit challenges are used. More about such extractors will be provided below.

### How can we prove that a protocol is ZKP

ZKP is proved by demonstrating that there exists a simulator which can simulate accepting transcripts (by interacting with a verifier and without knowing a secret) which cannot be distinguished from the transcripts between real prover and verifier.

In Schnorr protocol the simulator first chooses a random challenge c and random z, then it outputs the transcript $(g^z \times t^{-c}, c, z)$. The transcript is accepting and cannot be distinguished from a real conversation between prover and verifier. However, this is true only when verifier is choosing the challenge randomly. In case verifier has some other method to choose challenges, we cannot simulate the transcripts. For this reason Schnorr protocol is honest-verifier zero-knowledge proof (HVZKP).

Once again one-bit challenges come to the rescue (but of course this makes protocol much less efficient because multiple iterations are needed). The simulator in this case does not need to rely on the verifier being honest - it chooses a challenge and continues only if the verifier chooses the same challenge (the verifier is used as black-box). If different challenge is chosen by a verifier, the simulator aborts this execution of the protocol and goes from the beginning. Note that the chances that the simulator and verifier chooses the same challenge are 50%, so the simulator can provide accepting transcripts (actually, any sufficiently small challenge space
would do).

An alternative approach to make sigma protocol a ZKP is to use commitment scheme [2]. More about this will be provided below.

## Generalization of Schnorr protocol

Schnorr protocol can be generalized to general groups and one-way homomorphisms (homomorphism in Schnorr protocol being a function $x \to g^x \pmod p$ to prove the knowledge of homomorphism
preimage. Given a homomorphism $f: G \to H$ and $u$ from $H$, we want to prove that we know $v$ from $G$
such that $f(v) = u$.

The protocol goes:

- P chooses $r$ from $H$ and sends $m = f(r)$ to V.
- V chooses random $c$ and sends it to P.
- P sends $z = r \times v^c$ to V, who checks that $f(z) = m \times u^e$.

Note that this might be group with hidden order (like RSA, see `crypto/rsa` package), so one-bit challenges need to be used (making the protocol also ZKP).

In emmy this protocol is available in `crypto/preimage` package and can be executed as:

```go
prover := preimage.NewProver(homomorphism, H, v)
verifier := preimage.NewVerifier(homomorphism, H, u)

for j := 0; j < iterations; j++ {
	proofRandomData := prover.GetProofRandomData()
	verifier.SetProofRandomData(proofRandomData)
	challenge := verifier.GetChallenge()
	z := prover.GetProofData(challenge)
	if !verifier.Verify(z) {
		return false
	}
}

return true
```

This protocol is for example used by q-one-way commitment scheme [4] which uses the RSA group with hidden order, available in the same package (see `qoneway.Committer` and `qoneway.Receiver`). However, commitment schemes in groups with hidden order with more efficient proofs have been developed which do not require one-bit challenges, for example Damgard-Fujisaki [3].

## References

[1] C. Hazay and Y. Lindell. Efficient Secure Two-Party Computation: Techniques and Constructions. Springer, 2010.

[2] I. Damgard. Efficient concurrent zero-knowledge in the auxiliary string model. In B. Preneel, editor, Advances in Cryptology — EUROCRYPT 2000, volume 1807 of Lecture Notes in Computer Science, pages 431–444. Springer Verlag, 2000.

[3] I. Damgard and E. Fujisaki. An integer commitment scheme based on groups with hidden order. http://eprint.iacr.org/2001, 2001.

[4] Cramer, Ronald, and Ivan Damgård. "Zero-knowledge proofs for finite field arithmetic, or: Can zero-knowledge be for free?." Advances in Cryptology—CRYPTO'98. Springer Berlin/Heidelberg, 1998.
