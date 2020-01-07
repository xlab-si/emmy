# emmy - Library for zero-knowledge proofs 

<p align="center">
	<img src="emmy_logo.png" width="160" />
</p>

Emmy is a library for building protocols/applications based on zero-knowledge proofs, for example anonymous credentials.
Zero-knowledge proofs are **client-server protocols** (in crypto terms also *prover-verifier*, where the prover takes on 
the role of the client, and the verifier takes on the role of the server) where the client proves a knowledge
of a secret without actually revealing the secret.
  
Emmy also implements a communication layer supporting the execution of these protocols. 
Communication between clients and the server is based on [Protobuffers](https://developers.google.com/protocol-buffers/) and [gRPC](http://www.grpc.io/). 
Emmy server is capable of serving (verifying) thousands of clients (provers) concurrently. Currently, the communication 
is implemented for the two anonymous credential schemes (see [Currently offered cryptographic schemes](#currently-offered-cryptograhpic-schemes)).

In addition, emmy is built with **mobile clients** in mind, as it comes with *compatibility* 
package providing client wrappers and types that can be used for generating language bindings for 
Android or iOS mobile platforms. 

To get some more information about the theory behind zero knowledge proofs or developing 
various parts of emmy library, please refer to additional documentation in the *docs* folder.

#### What does emmy stand for?
Emmy library is named after a German mathematician [Emmy Noether](https://en.wikipedia.org/wiki/Emmy_Noether), recognised as one of the most important 20th century mathematicians. Emmy Noether's groundbreaking work in the field of abstract algebra earned her a nickname *the mother of modern algebra*. We named our library after her, since modern cryptography generally relies heavily on abstract algebraic structures and concepts.

<!-- toc -->
- [Currently offered cryptographic primitives](#currently-offered-cryptographic-primitives)
- [Currently offered cryptographic schemes](#currently-offered-cryptograhpic-schemes)
- [Installation](#installation)
- [emmy CLI tool](#using-the-emmy-cli-tool)
  * [emmy server](#emmy-server)
  * [emmy clients](#emmy-clients)
  * [TLS support](#tls-support)
- [Further documentation](#documentation)
<!-- tocstop -->

# emmy - anonymous credentials showcase
 
Let's say you would like to travel to some country which requires proof of vaccination for certain diseases.
You go to the clinic named South Loop Clinic, you get vaccinated and receive a proof that you are vaccinated. In fact, South Loop Clinic issues an anonymous credential which contains a proof that you have been vaccinated for certain diseases.

The credential would contain something like:

```
Name: Andrew
Surname: McCain
Age: 45
Gender: M
Vaccinated for yellow fever: true
```

Note that the credential does not contain attributes as plaintext - the credential is received from the
issuer by a zero-knowledge proof. When credential needs to be shown, another zero-knowledge proof
is executed. These protocols are unlinkable - issuer and verifier cannot determine
whether it is going on about the same credential (unless you reveal some unique attributes like address).
In fact, even when user connects two times using the same credential, the verifier cannot know that the same
credential has been used (that the same user is connecting).

Let's assume there is a smart phone app which offers a UI to the emmy protocols. 

To obtain a credential, user first need to create a master secret key. An app runs:

```
masterSecret := pubKey.GenerateUserMasterSecret()
```

Here, pubKey is the public key of a clinic (clinic instantiates an `Org` from `crypto/cl/org.go` and
uses it for issuing a credential).

The communication between user and clinic go for example over NFC - between user's phone and 
some clinic terminal.

User obtains a credential structure from a clinic (see `client/cl_test.go`):

```
rc, err := client.GetCredentialStructure()
```

Credential structure for `Org` is defined in `config/defaults.yml`.
User then fills the credential using an app and starts a protocol to obtain a credential:

```
name, _ := rc.GetAttr("Name")
name.UpdateValue("Andrew")

surname, _ := rc.GetAttr("Surname")
surnname.UpdateValue("McCain")

age, _ := rc.GetAttr("Age")
age.UpdateValue(45)

gender, _ := rc.GetAttr("Gender")
gender.UpdateValue("M")

vaccinated, _ := rc.GetAttr("Vaccinated")
vaccinated.UpdateValue("true") // vaccinated for yellow fever

cm, err := cl.NewCredManager(params, pubKey, masterSecret, rc)
cred, err := client.IssueCredential(cm, "testRegKey5")
```

The clinic verifies the validity of attributes and issues a credential. The verification in this case
is manual - an authorized person needs to verify the attributes and trigger the issuance of a credential.
User now possesses a credential on his phone.

When user arrives to a foreign country and a proof of vaccination is needed, he opens an app 
which runs:

```
acceptableCreds, err := client.GetAcceptableCreds()
```

The server returns a list of organizations whose credentials it accepts. Additionally, the attributes
that need to be revealed are specified:

```
revealedAttrs := acceptableCreds["South Loop Clinic"]
```

In our case this might be:

```
revealedAttrs = []string{"Vaccinated}
```

Now, the user can prove he has been vaccinated:

```
_, err := client.ProveCredential(cm, cred, revealedAttrs)
```

Verifier learns nothing about the user except that he was vaccinated for a certain disease.

# Currently offered cryptographic primitives

The library supports building complex cryptographic schemes. To enable this various layers are needed:

 * mathematical groups in which the operations take place
 * utilities for generating safe primes, group generators, for decomposing integers into squares (`crypto/common`)
 * commitments (to commit to a chosen value while keeping it hidden to others)
 * zero-knowledge proofs as building blocks for schemes (protocols which are used as subprotocols in schemes, see `crypto/zkp`)
 * communication layer to enable client-server interaction (for messages exchanged in protocols)
 
## Groups

The following groups are offered in appropriate subpackages of `crypto` package:

 * &#8484;<sub>n</sub>* (`zn.Group`) - group of all integers smaller than _n_ and coprime with _n_. In the special 
 case when _n_ is a prime, a specialized group `zn.GroupZp` may be used.
 * Schnorr group (`schnorr.Group`) - cyclic subgroup of &#8484;<sub>p</sub>; the order of Schnorr group is _q_ where _p = qr + 1_ for some _r_ (_p_, _q_ are primes); 
 the order of Schnorr group is smaller than of &#8484;<sub>p</sub> which means faster computations
 * RSA group (`rsa.Group`) - group of all integers smaller than _n_ and coprime with _n_, where _n_ is a product of two distinct large primes
 * QR RSA group (`qr.RSA`) - group of quadratic residues modulo _n_ where _n_ is a product of two primes
 * QR special RSA group (`qr.RSASpecial`) - group of quadratic residues modulo _n_ where _n_ is a product of two safe primes
 * Elliptic curve group (`ec.Group`) - wrapper around Go `elliptic.Curve`
 
## Commitments

The following commitments are offered in appropriate subpackages of `crypto` package:

 * Pedersen - for commitments in Schnorr group (supported &#8484;<sub>p</sub> and EC groups, see packages `pedersen`
 and `ecpedersen`, respectively) 
 * Damgard-Fujisaki [12] - for commitments in QR special RSA group (see package `df`)
 * Q-One-Way based [9] (see package `qoneway`). Note that Damgard-Fujisaki commitments should be used instead.
 
## Zero-knowledge proofs

 * Schnorr proofs for proving the knowledge of dlog [5],
dlog equality [7], dlog equality blinded transcript [4], and partial dlog knowledge [8]. All of these proofs
 work with both &#8484;<sub>p</sub> and EC groups (see packages `schnorr` and `ecschnorr`, respectively).
 * Proofs of knowledge of homomorphism preimage and knowledge of partial homomorphism preimage
  (see package `preimage`). These are generalizations of Schnorr proof to general
   groups and one-way homomorphisms.
 * Proof of knowledge of representation (generalized Schnorr for multiple bases) [10]
 * Damgard-Fujisaki proofs (package `df`) [12] - for proving that you can open a commitment, 
 that two commitments hide the same value, that a commitment contains a multiplication of two committed values, 
 that the committed value is positive, that the committed value is a square, commitment range based on Lipmaa [11]
 * QR special RSA representation proof (like Schnorr but in QR special RSA group, see `qr` package)
 * Quadratic residuosity and nonresiduosity (packages `qr` and `qnr`) [6]
 * Camenisch-Shoup verifiable encryption [1]
 
## Communication

Client-server communication code (based on gRPC) which enables execution of protocols over the internet is in 
`client` and `server` packages. The messages and services are defined in `proto` folder. Translations between
gRPC and native emmy messages are in `proto/translations.go`.

# Currently offered cryptographic schemes

Currently two anonymous credentials schemes are offered:
 
 * Pseudonym system [4] (see `crypto/zkp/schemes/pseudonymsys`) (offered in &#8484;<sub>p</sub> and EC groups)
 * Camenisch-Lysyanskaya anonymous credentials [2][15] (see `crypto/cl`) - work in progress
 
Pseudonym system [4] was the first anonymous credential scheme and was superseded by Camenisch-Lysyanskaya scheme [2].

## Camenisch-Lysyanskaya anonymous credentials

What are anonymous credentials:

 * user gets a certificate which contains personal data (name, gender, nationality, age ... )
 * the same certificate can be used to connect to different services (even if the databases are joined service providers 
 cannot map/link the users)
 * when connecting to a service, user can choose which data to reveal - some services might require only the possession 
 of a certificate (e.g. certifying that user paid for something), others might require some subset of data contained in certificate
 
While anonymity is obviously a MUST in e-voting, it might gradually become more important in other scenarios as well: 

 * online subscriptions 
 * wearable healthcare (for example sending diabetes data to a research team)
 * vehicle communications - cars sending out data about traffic
 
### CL scheme - brief overview how it works

There are public parameters _Z_, _S_, _R1_, ... , _Rl_.

Issuer (of a credential) computes _Q_ based on public parameters, user attributes and random _v_:

```
Q = (Z / (R1^attr1 * ... * Rl^attrl * S^v)
```

Issuer then chooses random prime _e_ (which is as public key in RSA algorithm), computes _d_ such that:

```
x^(e*d) = x (mod n)
```

Issuer then computes _A_ (as in RSA signature):

```
A = Q^d
```

The credential in the form of a triplet _(A, e, v)_ is then given to a user.

The organization that checks the validation of a user's credential checks whether:

```
A^e = Q = (Z / (R1^attr1 * ... * Rl^attrl * S^v) 
```

If only a subset of attributes are revealed, zero-knowledge proof is applied - on the right side of the equation only
a subset of attributes is known, thus the user needs to prove the knowledge of attributes such that the equation holds.

# Warning
_All components of emmy cryptography library are a work in progress. At this point, the library can be used to build proof of concept implementations for research purposes and **should never be used in production**. Project's code organization and library APIs are **not stable** - they are expected to undergo major changes, and may be changed at any point._
 
# Installation
To install emmy, run 

```
$ go get github.com/xlab-si/emmy
```

This should give you the `emmy` executable in your `$GOBIN`.
You can run the unit tests to see if everything is working properly with:

```
$ go test ./...
```

# Using the emmy CLI tool

Below we provide some isntructions for using the `emmy` CLI tool. You can type `emmy` in the terminal to get a list of available commands and subcommands, and to get additional help.

Emmy CLI offers two commands:
* `emmy server` (with a `start` subcommand, e.g. `emmy server start`) and
* `emmy client` (with subcommand `info`).
> **Note:** emmy client command is currently going through a major revision. Running clients for
    demo interactive protocols (_pedersen_, _pedersen_ec_, _schnorr_, _schnorr_ec_ _cspaillier_) is
     no longer supported. Instead, clients for running protocols comprising anonymous 
     authentication schemes will be added soon.


## emmy server

Emmy server waits for requests from clients (provers) and starts verifying them. Note that emmy server connects to a redis database in order to verify the registration keys, provided in the nym generation process. Redis is expected to run at localhost:6379 (or as defined in [defaults.yml](config/defaults.yml)).

```bash
$ emmy server              # prints available subcommands
$ emmy server start --help # prints subcommand flags, their meaning and default values
```

To start emmy server with the default options, run 

```bash
$ emmy server start        # starts emmy server with default settings
```

Alternatively, you can control emmy server's behavior with the following options (specified as command line flags):
1. **Port**: flag *--port* (shorthand *-p*), defaults to 7007.

    Emmy server will listen for client connections on this port. Example: 
    ```bash
    $ emmy server start --port 2323   # starts emmy server that listens on port 2323
    $ emmy server start -p 2323       # equivalently
    ```
2. **Logging level**: flag *--loglevel* (shorthand *-l*), which must be one of `debug|info|notice|error|critical`. Defaults to `ìnfo`.

    For development or debugging purposes, we might prefer more fine-grained logs, in which case we would run:
    ```bash
    $ emmy server start --loglevel debug # or shorthand '-l debug'
    ```
3. **Log file**: flag *--logfile*, whose value is a path to the file where emmy server will output logs in addition to standard output. If the file does not exist, one is created. If it exists, logs will be appended to the file. It defaults to empty string, meaning that the server will not write output to any file.

    Example:
    ```bash
    $ emmy server start --loglevel debug --logfile ~/emmy-server.log
    ```

4. **Certificate and private key**: flags *--cert* and *--key*, whose value is a path to a valid certificate and private key in PEM format. These will be used to secure communication channel with clients. Please refer to [explanation of TLS support in emmy](#tls-support) for explanation.

5. **Address of the redis database**: flag *--db* of the form *redisHost:redisPort*, which points
 to a running instance of redis database that holds [registration keys](#registration-keys). 
 Defaults to *localhost:6379*.

Starting the server should produce an output similar to the one below:

```
(1) [server][Mon 25.Sep 2017,14:11:041] NewProtocolServer ▶ INFO  Instantiating new protocol server
(2) [server][Mon 25.Sep 2017,14:11:041] NewProtocolServer ▶ INFO  Successfully read certificate [test/testdata/server.pem] and key [test/testdata/server.key]
(3) [server][Mon 25.Sep 2017,14:11:041] NewProtocolServer ▶ NOTI  gRPC Services registered
(4) [server][Mon 25.Sep 2017,14:11:041] EnableTracing ▶ NOTI  Enabled gRPC tracing
(5) [server][Mon 25.Sep 2017,14:11:041] Start ▶ NOTI  emmy server listening for connections on port 7007
```

Line 1 indicates that the emmy server is being instantiated. Line 2 informs us about the server's certificate and private key paths to be used for secure communication with clients. Line 3 indicates that gRPC service for execution of crypto protocols is ready, and Line 4 tells us that gRPC tracing (used to oversee RPC calls) has been enabled. Finaly, line 5 indicates that emmy server is ready to serve clients.

When a client establishes a connection to emmy server and starts communicating with it, the server will log additional information. How much gets logged depends on the desired log level. 

You can stop emmy server by hitting `Ctrl+C` in the same terminal window.

#### Registration keys

Emmy server verifies registration keys provided by clients when initiating the nym generation procedure. A separate server is expected to provide registration keys to clients via another channel (e.g. QR codes on physical person identification) and save the generated keys to a registration database, read by the emmy server.


## emmy clients (DEPRECATED)

Running a client requires an instance of emmy server. First, spin up emmy server according to instructions in the previous section. You can then start one or more emmy clients in another terminal. 

We use commands of the following form to start emmy clients:

```bash
$ emmy client <commonClientFlags> protocolSubcommand <protocolFlags> 
```

where *commonClientFlags* control the following aspects:

1. **How many clients to start**: flag *--nclients* (shorthand *-n*), defaults to 1.
2. **Whether to run clients concurrently or not**: flag *--concurrent*. Include this flag if you want to run the specified number of clients consurrently. The absence of this flag means that clients will be run sequentially.
3. **Logging level**: flag *--loglevel* (shorthand *-l*), which must be one of `debug|info|notice|error|critical`. Defaults to `ìnfo`.
4. **URI of the emmy server**: flag *--server*, defaults to *localhost:7007*.
5. **CA certificate**: flag *--cacert*, points to a path to a certificate of the CA that issued emmy server's certificate, in PEM format. This will be used to secure communication channel with the server. Please refer to [explanation of TLS support in emmy](#tls-support) for explanation.
6. **Server name override**: flag *--servername*. This will instruct clients to check server 
certificate's common name (CN) against the value of the provided flag, instead of server's 
hostname. Allows certificate validation to pass even when server's hostname does not 
match the CN specified in server's certificate. 

    > This should only be used for connecting clients to emmy development server, for instance
    where self-signed certificate is used, or when the CN in server's certificate is not resolvable.
7. **Whether to use system's certificate pool**: flag *--syscertpool*. When present, the 
values of `--cacert` and `--servername` will be ignored. 
8. **Connection timeout**: flag *--timeout* (shorthand *-t*), indicating a timeout (in milliseconds)
 for establishing connection with emmy server. Client fails if connection cannot be established before
 the timeout. Defaults to *5000 milliseconds*.

Moreover, the *protocolSubcommand* corresponds to a concrete protocol that we want to demonstrate between emmy client and emmy server. You can list valid *protocolSubcommand* values by running 

```bash
$ emmy client --help 
```

To get more info on *protocolFlags* that the chosen *protocolCommand* supports, run `emmy client <protocolCommand> --help`, for instance

```bash
$ emmy client pedersen --help
```

and you will se additional flags that you can provide as input to bootstrap appropriate protocol. Usually, you can provide some sort of a secret value via the flag *--secret*, and the protocol variant to execute via the flag *--variant* (shorthand *-v*), denoting whether to execute sigma protocol, zero-knowledge proof or zero-knowledge proof of knowledge (`sigma|zkp|zkpok`, defaults to `sigma`).

Below we give some examples that run emmy client in order to demonstrate Schnorr protocol:
```
$ emmy client schnorr #Runs sigma protocol with the default values
$ emmy client --loglevel debug schnorr 
$ emmy client -l debug schnorr --variant zkp --secret 32432
$ emmy client -l debug schnorr -v zkp --secret 32432
```

Here are some more fun examples:
```
$ emmy client --nclients 5 schnorr -v zkpok
$ emmy client -n 5 schnorr -v zkpok # this one is equivalent to the one above
$ emmy client -n 5 --concurrent schnorr -v zkpok
```

And here is some example output of the `emmy client` command:
```
$ emmy client --server localhost:7007 pedersen
(1) GetConnection ▶ INFO  Getting the connection
(2) GetConnection ▶ NOTICE  Established connection to gRPC server
(3) ***Running client #1***
(4) send ▶ INFO  [Client 1257061046] Successfully sent request of type *protobuf.Message_Empty
(5) receive ▶ INFO  [Client 1257061046] Received response of type *protobuf.Message_PedersenFirst from the stream
(6) send ▶ INFO  [Client 1257061046] Successfully sent request of type *protobuf.Message_Bigint
(7) receive ▶ INFO  [Client 1257061046] Received response of type *protobuf.Message_Empty from the stream
(8) send ▶ INFO  [Client 1257061046] Successfully sent request of type *protobuf.Message_PedersenDecommitment
(9) receive ▶ INFO  [Client 1257061046] Received response of type *protobuf.Message_Status from the stream
(10) ***Time: 0.003153414 seconds***
```

Lines 1-2 tell us about the procedure of initializing, and eventually, establishing a connection to emmy server at the given URI. Line 3 comes from the emmy CLI, and notifies us that the protocol client is about to start. Lines 4-9 indicate the communication taking place between the client and the server (e.g. here they are executing the chosen crypto protocol). The last line reports the total time required to execute the protocol - if we run several clients (either sequentially or concurrently), it prints the total time required for all the clients to finish.

## TLS support
Communication channel between emmy clients and emmy server is secure, as it enforces the usage of TLS. TLS is used to encrypt communication and to ensure emmy server's authenticity.

By default, the server will attempt to use the private key and certificate in `test/testdata` directory. The provided certificate is self-signed, and therefore the clients can use it as the CA certificate (e.g. certificate of the entity that issued server's certificate) which they have to provide in order to authenticate the server.
 >**Important note:** You should never use the private key and certificate that comes with this repository when running emmy in production. These are meant *for testing and development purposes only*.

In a real world setting, the client needs to keep a copy of the CA certificate which issued server's certificate. When the server presents its certificate to the client, the client uses CA's certificate to check the validity of server's certifiacate.

To control keys and certificates used for TLS, emmy CLI programs use several flags. In addition to those already presented in this document, `emmy server` supports the following flags:

* `--cert` which expects the path to server's certificate in PEM format, 
* `--key` which expects the path to server's private key file.

On the other hand, we can provide `emmy client` with the following flags:
* `--cacert`, which expects the path to certificate of the CA that issued emmy server's certificate 
(in PEM format). Again, if this flag is omitted, the certificate in `test/testdata` directory is used.
* `--servername`, which instructs the client to skip validation of the server's hostname. In the 
absence of this flag, client will always check whether the server's hostname matches 
the common name (CN) specified in the server's certificate as a part of certificate validation. For 
development purposes, hostname and server's CN will likely not match, and thus it is convenient to 
provide a `--servername` flag with the value matching the CN specified in the server's certificate.
* `--syscertpool`, which tells the client to look for the CA certificate in the host system's 
certificate pool. If this flag is provided, the presence of `--cacert` or `--servername` flags 
will be ignored. In addition, the CA certificate needs to be put in the system's default 
certificate store location beforehand.
  
  To give you an example, let's try to run an emmy client against an instance of emmy server that uses the self-signed certificate shipped with this repository. The hostname in the certificate is *localhost*, but the server is deployed on a host other than localhost (for instance, *10.12.13.45*). When we try to contact the server withour the *--insecure* flag, here's what happens:

  ```bash
  $ emmy client --server 10.12.13.45:7007 schnorr

  2017/09/13 12:48:47 [client] 12:48:47.232 GetConnection ▶ INFO 001 Getting the connection
  Cannot connect to gRPC server: Could not connect to server 10.12.13.45:7007 (x509: cannot validate certificate for 10.12.13.45 because it doesnt contain any IP SANs)
  ```

  Now let's include the *--insecure* flag, and the (insecure) connection to the server is now successfully established.

  ```bash
  $ emmy client --server 10.10.43.45:7007 --insecure schnorr

  2017/09/14 09:02:01 [client] 09:02:01.153 GetConnection ▶ INFO 001 Getting the connection
  2017/09/14 09:02:01 [client] 09:02:01.153 GetConnection ▶ WARN 002 ######## You requested an **insecure** channel! ########
  2017/09/14 09:02:01 [client] 09:02:01.153 GetConnection ▶ WARN 003 As a consequence, server's identity will *NOT* be validated!
  2017/09/14 09:02:01 [client] 09:02:01.153 GetConnection ▶ WARN 004 Please consider using a secure connection instead
  2017/09/14 09:02:01 [client] 09:02:01.162 GetConnection ▶ NOTI 005 Established connection to gRPC server
  ```

# Documentation
* [A short overview of the theory emmy is based on](./docs/theory.md) 
* [Developing emmy (draft)](./docs/develop.md) 

# Roadmap

 * Improve the database layer supporting persistence of cryptographic material (credentials, pseudonyms, ...)
 * Refactor Camenisch-Lysyanskaya scheme (database records, challenge generation ... )
 * Additional proofs for Camenisch-Lysyanskaya scheme (range proof for attributes ... )
 * Revocation for Camenisch-Lysyanskaya scheme
 * Attribute types in Camenisch-Lysyanskaya scheme (string, int, date, enum)
 * Performance optimization (find bottlenecks and fix them)
 * Efficient attributes for anonymous credentials [15]
 * Camenisch-Lysyanskaya scheme based on pairings [14]
 * Fix Camenisch-Shoup verifiable encryption (it was implemented before many of the primitives were available)

# References

[1] J. Camenisch and V. Shoup, Practical verifiable encryption and decryption of discrete logarithms, http://eprint.iacr.org/2002/161, 2002.

[2] J. Camenisch and A. Lysyanskaya. A signature scheme with efficient protocols. In S. Cimato, C. Galdi, and G. Persiano, editors, Security in Communication Networks, Third International Conference, SCN 2002, volume 2576 of LNCS, pages 268–289. Springer Verlag, 2003.

[3] D. Chaum and T. P. Pedersen, Wallet databases with observers, Advances in Cryptology — CRYPTO ’92 (E. F. Brickell, ed.), LNCS, vol. 740, Springer-Verlag, 1993, pp. 89– 105.

[4] A. Lysyanskaya, R. Rivest, A. Sahai, and S. Wolf. Pseudonym systems. In Selected Areas in Cryptography, vol. 1758 of LNCS. Springer Verlag, 1999.

[5] C. P. Schnorr. Efficient Identification and Signatures for Smart Cards. In Crypto ’89, LNCS 435, pages 235–251. Springer-Verlag, Berlin, 1990. 

[6] Goldwasser, Shafi, Silvio Micali, and Charles Rackoff. "The knowledge complexity of interactive proof systems." SIAM Journal on computing 18.1 (1989): 186-208.

[7] D. Chaum and T. P. Pedersen, Wallet databases with observers, Advances in Cryptology — CRYPTO ’92 (E. F. Brickell, ed.), LNCS, vol. 740, Springer-Verlag, 1993, pp. 89– 105.

[8] Cramer, Ronald, Ivan Damgård, and Berry Schoenmakers. "Proofs of partial knowledge and simplified design of witness hiding protocols." Advances in Cryptology—CRYPTO’94. Springer Berlin/Heidelberg, 1994.

[9] Cramer, Ronald, and Ivan Damgård. "Zero-knowledge proofs for finite field arithmetic, or: Can zero-knowledge be for free?." Advances in Cryptology—CRYPTO'98. Springer Berlin/Heidelberg, 1998.

[10] Brands, Stefan A. "An efficient off-line electronic cash system based on the representation problem." (1993): 01-16.

[11] Helger Lipmaa. On diophantine complexity and statistical zero-knowledge arguments. In ASIACRYPT, volume 2894 of Lecture Notes in Computer Science, pages 398–415. Springer, 2003.

[12] I. Damgård and E. Fujisaki. An integer commitment scheme based on groups with hidden order. http://eprint.iacr.org/2001, 2001.

[13] I. Damgård. Efficient concurrent zero-knowledge in the auxiliary string model. In B. Preneel, editor, Advances in Cryptology — EUROCRYPT 2000, volume 1807 of Lecture Notes in Computer Science, pages 431–444. Springer Verlag, 2000.

[14] Camenisch, Jan, and Anna Lysyanskaya. "Signature schemes and anonymous credentials from bilinear maps." Annual International Cryptology Conference. Springer, Berlin, Heidelberg, 2004.

[15] Camenisch, Jan, and Thomas Groß. "Efficient attributes for anonymous credentials." Proceedings of the 15th ACM conference on Computer and communications security. ACM, 2008.
