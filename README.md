# emmy - Library for sigma protocols and zero-knowledge proofs [![Build Status](https://travis-ci.org/xlab-si/emmy.svg?branch=master)](https://travis-ci.org/xlab-si/emmy)

Emmy is a library that offers a **crypto-backend** with primitives for implementation of various cryptographic proofs and **client-server protocols** (in crypto terms also *prover-verifier*, where the prover takes on the role of the client, and the verifier takes on the role of the server). It can be used in scenarios like *anonymous digital credentials*. Emmy also implements a communication layer supporting the execution of these protocols. 

Communication between clients and the server is based on [Protobuffers](https://developers.google.com/protocol-buffers/) and [gRPC](http://www.grpc.io/). Emmy server is capable of serving (verifying) thousands of clients (provers) concurrently. 

The library comes with a convenient CLI for running *emmy server* and *emmy client*s that demonstrates the execution of protocols between clients and the server.

To get some more information about the theory behind zero knowledge proofs, please refer to additional documentation in the *docs* folder.

#### What does emmy stand for?
Emmy library is named after a German mathematician [Emmy Noether](https://en.wikipedia.org/wiki/Emmy_Noether), recognised as one of the most important 20th century mathematicians. Emmy Noether's groundbreaking work in the field of abstract algebra earned her a nickname *the mother of modern algebra*. We named our library after her, since modern cryptography generally relies heavily on abstract algebraic structures and concepts.

<!-- toc -->
- [Installation](#installation)
- [Currently supported crypto primitives](#currently-supported-crypto-primitives)
- [Emmy CLI tool](#using-the-emmy-cli-tool)
  * [Emmy server](#emmy-server)
  * [Emmy clients](#emmy-clients)
  * [TLS support](#tls-support)
- [Further documentation](#documentation)
<!-- tocstop -->

# Installation
To install emmy, run 

```
$ go get github.com/xlab-si/emmy
```

This should give you the `emmy` executable in your `$GOBIN`. Afterwards you can run the unit tests to see if everything is working properly with:

```
$ go test -v test/*.go
```

# Currently supported crypto primitives

The crypto primitives and schemes (schemes are primitives combined in some more complex protocol) supported by emmy are listed in the table below.
ZKP primitives and schemes are collected in `crypto/zkp/primitives` and `crypto/zkp/schemes` respectively.
Each of the ZKP primitives contains a function (at the beginning of the file) which demonstrates how proof should be executed. Client-server communication via gRPC which enable execution of ZKPs over the internet is in `client` and `server` packages.

Note that the primitives not ticked are implemented, but without client-server communication via gRPC. 
Primitives are meant to be used in schemes (like Schnorr, DLogEquality and others in Pseudonymsys) and communication messages for primitives are implemented there 
(different schemes might require slightly different messages).

>**Note**: &#8484;<sub>p</sub> = multiplicative group of integers modulo prime p, EC = Elliptic Curve, ZKP = Zero Knowledge Proof, ZKPOK = Zero Knowledge Proof Of Knowledge

| Primitives |
| ----- |
| [✓] Schnorr protocol [5] (&#8484;<sub>p</sub> and EC)(sigma protocol can be turned into ZKP and ZKPOK) |
| [✓] Pedersen commitments (&#8484;<sub>p</sub> and EC) |
| [✓] ZKP of quadratic residuosity [6] |
| [✓] ZKP of quadratic nonresiduosity [6] |
| [✓] Chaum-Pedersen for proving dlog equality [7] (&#8484;<sub>p</sub> and EC) | 
| [✓] DLog Equality Blinded Transcript [4] (&#8484;<sub>p</sub> and EC) | 
| [✓] Pseudonym system [4] (&#8484;<sub>p</sub> and EC) |
| [✗] Proof of partial dlog knowledge [8] (&#8484;<sub>p</sub> and EC) |
| [✓] Camenisch-Shoup verifiable encryption (cspaillier) [1] |
| [✗] Camenisch-Lysyanskaya signature [2] |
| [✗] Q-One-Way based commitments (with bit commitment and multiplication proof) [9] |
| [✗] Proof of knowledge of representation (generalized Schnorr for multiple bases) [10] |
| [✗] Shamir's secret sharing scheme |


# Using the emmy CLI tool

Below we provide some isntructions for using the `emmy` CLI tool. You can type `emmy` in the terminal to get a list of available commands and subcommands, and to get additional help.

Emmy CLI offers two commands:
* `emmy server` (with a `start` subcommand, e.g. `emmy server start`) and
* `emmy client` (with subcommands `pedersen`, `pedersen_ec`, `schnorr`, `schnorr_ec`, `cspaillier`).

## Emmy server

Emmy server waits for requests from clients (provers) and starts verifying them.

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

4. **Certificate and private key**: flags *--cert* and *--key*, whose value is a path to a valid certificate and private key in PEM format. These will be used to secure communication channel with clients. Please refer to [explanation of TLS support in Emmy](#tls-support) for explanation.

Starting the server should produce an output similar to the one below:

```
(1) [server][Mon 25.Sep 2017,14:11:041] NewProtocolServer ▶ INFO  Instantiating new protocol server
(2) [server][Mon 25.Sep 2017,14:11:041] NewProtocolServer ▶ INFO  Successfully read certificate [test/testdata/server.pem] and key [test/testdata/server.key]
(3) [server][Mon 25.Sep 2017,14:11:041] NewProtocolServer ▶ NOTI  gRPC Services registered
(4) [server][Mon 25.Sep 2017,14:11:041] EnableTracing ▶ NOTI  Enabled gRPC tracing
(5) [server][Mon 25.Sep 2017,14:11:041] Start ▶ NOTI  Emmy server listening for connections on port 7007
```

Line 1 indicates that the emmy server is being instantiated. Line 2 informs us about the server's certificate and private key paths to be used for secure communication with clients. Line 3 indicates that gRPC service for execution of crypto protocols is ready, and Line 4 tells us that gRPC tracing (used to oversee RPC calls) has been enabled. Finaly, line 5 indicates that emmy server is ready to serve clients.

When a client establishes a connection to emmy server and starts communicating with it, the server will log additional information. How much gets logged depends on the desired log level. 

You can stop emmy server by hitting `Ctrl+C` in the same terminal window.


## Emmy clients

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
5. **CA certificate**: flag *--cacert*, points to a path to a certificate of the CA that issued emmy server's certificate, in PEM format. This will be used to secure communication channel with the server. Please refer to [explanation of TLS support in Emmy](#tls-support) for explanation.
6. **Allowing insecure connections**: flag *--insecure*. In the absence of this flag clients will check emmy server's hostname and CA certificate chain. If you include this flag, none of these checks will be performed.
  
    > This should only be used for connecting clients to emmy development server, where self-signed certificate is used.

Moreover, the *protocolSubcommand* corresponds to a concrete crypto protocol that we want to demonstrate between emmy client and emmy server. You can list valid *protocolSubcommand* values by running 

```bash
$ emmy client --help 
```

To get more info on *protocolFlags* that the chosen *protocolCommand* supports, run `emmy client <protocolCommand> --help`, for instance

```bash
$ emmy client pedersen --help
```

and you will se additional flags that you can provide as input to bootstrap appropriate protocol. Usually, you can provide some sort of a secret value via the flag *--secret*, and the protocol variant to execute via the flag *--variant* (shorthand *-v*), denoting whether to execute sigma protocol, zero-knowledge proof or zero-knowledge proof of knowledge (`sigma|zkp|zkpok`, defaults to `sigma`).

Below we give some examples that run Emmy client in order to demonstrate Schnorr protocol:
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

Lines 1-2 tell us about the procedure of initializing, and eventually, establishing a connection to Emmy server at the given URI. Line 3 comes from the Emmy CLI, and notifies us that the protocol client is about to start. Lines 4-9 indicate the communication taking place between the client and the server (e.g. here they are executing the chosen crypto protocol). The last line reports the total time required to execute the protocol - if we run several clients (either sequentially or concurrently), it prints the total time required for all the clients to finish.

## TLS support
Communication channel between emmy clients and emmy server is secure, as it enforces the usage of TLS. TLS is used to encrypt communication and to ensure emmy server's authenticity.

By default, the server will attempt to use the private key and certificate in `test/testdata` directory. The provided certificate is self-signed, and therefore the clients can use it as the CA certificate (e.g. certificate of the entity that issued server's certificate) which they have to provide in order to authenticate the server.
 >**Important note:** You should never use the private key and certificate that comes with this repository when running emmy in production. These are meant *for testing and development purposes only*.

In a real world setting, the client needs to keep a copy of the CA certificate which issued server's certificate. When the server presents its certificate to the client, the client uses CA's certificate to check the validity of server's certifiacate.

To control keys and certificates used for TLS, emmy CLI programs use several flags. In addition to those already presented in this document, `emmy server` supports the following flags:

* `--cert` which expects the path to server's certificate in PEM format, 
* `--key` which expects the path to server's private key file.

On the other hand, we can provide `emmy client` with the following flags:
* `--cacert`, which expects the certificate of the CA that issued emmy server's certificate (in PEM format). Again, if this flag is omitted, the certificate in `test/testdata` directory is used.
* `--insecure`, which tells the client not to check the CA certificate chain or emmy server's hostname. This option is meant for development purposes only, for instance when we have deployed emmy server with a self-signed certificate to a host whose hostname does not match the hostname specified in the server's certificate (for instance, *localhost*).
  
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
* [A short overview of the theory Emmy is based on](./docs/theory.md) 
* [Developing Emmy (draft)](./docs/develop.md) 

# References

[1] J. Camenisch and V. Shoup, Practical verifiable encryption and decryption of discrete logarithms, http://eprint.iacr.org/2002/161, 2002.

[2] J. Camenisch and A. Lysyanskaya. A signature scheme with efficient protocols. In S. Cimato, C. Galdi, and G. Persiano, editors, Security in Communication Networks, Third International Conference, SCN 2002, volume 2576 of LNCS, pages 268–289. Springer Verlag, 2003.

[3] D. Chaum and T. P. Pedersen, Wallet databases with observers, Advances in Cryptology — CRYPTO ’92 (E. F. Brickell, ed.), LNCS, vol. 740, Springer-Verlag, 1993, pp. 89– 105.

[4] A. Lysyanskaya, R. Rivest, A. Sahai, and S. Wolf. Pseudonym systems. In Selected Areas in Cryptography, vol. 1758 of LNCS. Springer Verlag, 1999.

[5] C. P. Schnorr. Efficient Identification and Signatures for Smart Cards. In Crypto ’89, LNCS 435, pages 235–251. Springer-Verlag, Berlin, 1990. [2] P. Paillier, Public-key cryptosystems based on composite residuosity classes, Advances in Cryptology — EUROCRYPT ’99, LNCS, vol. 1592, Springer Verlag, 1999, pp. 223–239. [3] K. IRELAND AND M. ROSEN, A Classical Introduction to Modern Number Theory, Springer-Verlag, New York, 2nd edition, 1990.

[6] Goldwasser, Shafi, Silvio Micali, and Charles Rackoff. "The knowledge complexity of interactive proof systems." SIAM Journal on computing 18.1 (1989): 186-208.

[7] D. Chaum and T. P. Pedersen, Wallet databases with observers, Advances in Cryptology — CRYPTO ’92 (E. F. Brickell, ed.), LNCS, vol. 740, Springer-Verlag, 1993, pp. 89– 105.

[8] Cramer, Ronald, Ivan Damgård, and Berry Schoenmakers. "Proofs of partial knowledge and simplified design of witness hiding protocols." Advances in Cryptology—CRYPTO’94. Springer Berlin/Heidelberg, 1994.

[9] Cramer, Ronald, and Ivan Damgård. "Zero-knowledge proofs for finite field arithmetic, or: Can zero-knowledge be for free?." Advances in Cryptology—CRYPTO'98. Springer Berlin/Heidelberg, 1998.

[10] Brands, Stefan A. "An efficient off-line electronic cash system based on the representation problem." (1993): 01-16.

