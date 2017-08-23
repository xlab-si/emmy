# emmy - Library for sigma protocols and zero-knowledge proofs [![Build Status](https://travis-ci.org/xlab-si/emmy.svg?branch=master)](https://travis-ci.org/xlab-si/emmy)

Emmy is a library that offers a **crypto-backend** with primitives for implementation of various cryptographic proofs and **client-server protocols** (in crypto terms also *prover-verifier*, where the prover takes on the role of the client, and the verifier takes on the role of the server). It can be used in scenarios like *anonymous digital credentials*. Emmy also implements a communication layer supporting the execution of these protocols. 

Communication between clients and the server is based on [Protobuffers](https://developers.google.com/protocol-buffers/) and [gRPC](http://www.grpc.io/). Emmy server is capable of serving (verifying) thousands of clients (provers) concurrently. 

The library comes with a convenient CLI for running *emmy server*, *emmy clients* or full examples demonstrating communication between clients and the server.

To get some more information about the theory behind zero knowledge proofs, please refer to additional documentation in the *docs* folder.

#### What does emmy stand for?
Emmy library is named after a German mathematician [Emmy Noether](https://en.wikipedia.org/wiki/Emmy_Noether), recognised as one of the most important 20th century mathematicians. Emmy Noether's groundbreaking work in the field of abstract algebra earned her a nickname *the mother of modern algebra*. We named our library after her, since modern cryptography generally relies heavily on abstract algebraic structures and concepts.

# Installation
To install emmy, run 

```
go get github.com/xlab-si/emmy
```

This should give you the `emmy` executable in your `$GOBIN`. Afterwards you can run the unit tests to see if everything is working properly with:

```
go test -v test/*.go
```

# Using the emmy CLI tool
Below we provide isntructions for using the `emmy` CLI tool. In addition, you can type `emmy` in the terminal to get a list of available commands and subcommands, and to get additional help.

## Emmy server
Emmy server waits for requests from clients (provers) and starts verifying them.

```bash
$ emmy server        # prints available commands, options and default values
$ emmy server start  # starts emmy server with default settings
```

Alternatively, to control what gets logged server-side, you can provide the flag `--loglevel` (shorthand `-l`) with one of the values `debug|info|notice|error|critical`. For instance, for development or debugging purposes we might prefer more fine-grained logs, in which case we would run


```bash
$ emmy server start --loglevel debug # or shorthand '-l debug'
```

If this flag is omitted, the log level defaults to `info`.

Starting the server should produce an output similar to the one below:

```
(1) 2017/06/06 10:57:08 [server] 10:57:08.184 startEmmyServer ▶ INFO 001 Registering services
(2) 2017/06/06 10:57:08 [server] 10:57:08.184 NewProtocolServer ▶ INFO 002 Instantiating new protocol server
(3) 2017/06/06 10:57:08 [server] 10:57:08.184 startEmmyServer ▶ INFO 003 Emmy server listening for connections on port 7007

```

Line 1 indicates that gRPC service for execution of crypto protocols is about to begin. Line 2 indicates that the emmy server is being instantiated, and Line 3 indicates that emmy server is ready to serve clients.

When a client establishes a connection to the emmy server and starts communicating with it, the server will log additional information. This includes any errors that might occur, and the payload recieved from client's requests or sent back in the responses to the client. 

You can stop emmy server by hitting `Ctrl+C` in the same terminal window.


## Emmy client(s)
Running the clients requires an instance of emmy server. First, spin up the emmy server according to the instructions in the previous section. You can then start emmy clients in another terminal. We use the `emmy client <list of flags>` command to start client(s), where flags are used to specify:

1. **Which protocol to run**: flags *--protocol* (shorthand *-p*) which must be one of `pedersen|pedersen_ec|schnorr|schnorr_ec|cspaillier` and defaults to pedersen, and flag *--variant* (shorthand *-v*) which must be one of `sigma|zkp|zkpok` and defaults to sigma. 
2. **How many clients to start**: flag *--nclients* (shorthand *-n*), defaults to 1.
3. **Whether to run clients concurrently or not**: flag *--concurrent*. Include this flag if you want to run the specified number of clients consurrently. The absence of this flag means that clients will be run sequentially.
4. **Logging level**: flag *--loglevel* (shorthand *-l*), which must be one of `debug|info|notice|error|critical`. Defaults to `ìnfo`.

You can also list these flags and their default values by running `emmy client --help`.

Here are some equivalent examples:
```
$ emmy client  # Runs the default client, which is a single client for pedersen sigma protocol
$ emmy client --protocol pedersen --variant sigma --nclients 1
$ emmy client -p pedersen -v sigma -n 1
```

Here are some more fun examples (again, these are equivalent):
```
$ emmy client --protocol schnorr --variant zkp --nclients 100 --concurrent
$ emmy client -p schnorr -v zkp -n 100 --concurrent
```

And here is some example output of the `emmy client` command:
```
(1) 2017/06/06 11:27:49 [client] 11:27:49.867 runClients ▶ INFO 001 Running client #0
(2) 2017/06/06 11:27:49 [client] 11:27:49.867 NewProtocolClient ▶ DEBU 002 Creating client [SchemaType = PEDERSEN][SchemaVariant = SIGMA]
(3) 2017/06/06 11:27:49 [client] 11:27:49.867 getConnection ▶ DEBU 003 Getting the connection
(4) 2017/06/06 11:27:49 [client] 11:27:49.868 NewProtocolClient ▶ DEBU 004 Creating the client
(5) 2017/06/06 11:27:49 [client] 11:27:49.868 getStream ▶ DEBU 005 Getting the stream
(6) 2017/06/06 11:27:49 [client] 11:27:49.868 NewProtocolClient ▶ INFO 006 NewProtocol client spawned (877641953)
(7) 2017/06/06 11:27:49 [client] 11:27:49.868 ExecuteProtocol ▶ INFO 007 Starting client [877641953] PEDERSEN (SIGMA)
(8) 2017/06/06 11:27:49 [client] 11:27:49.868 send ▶ INFO 008 [Client 877641953] Successfully sent request:%!(EXTRA *comm.Message=empty:<> clientId:877641953 )
(9) 2017/06/06 11:27:49 [client] 11:27:49.869 receive ▶ INFO 009 [Client 877641953] Received response from the stream: pedersen_first:<H:">\335\001\215d_\345\020\026^\226?t\241\205\360I\246,#(\277&\367d\350\314\306\215\323\263\177\006\256\t?\244\033\245\223\014\373\023\000\024S[\330\325\r\311\017\220\3635\277\035\035\343\341\330\376r\275\334b~i\377\266(\035B\033\301\304\250\323\003k\237T\340\206\026$\357\206\352j\231\372\206\020E\026\0009\244\252\037\300\335Z\214\247/\201\376\004\250\335\340\222\027\003Md\253~\027\020\201\250y\370\357\232*(0\023LK\345\r&\246\246D\324H&mQ\341\353\353\354N9@\255\355\224\313\254\247n\254\266A\221\335\206\270\357u\375\234\256\276\271)\024'\317\324\241\204\313Xx\013\335\007'U\337^Y\243\272+\020\351p\004\254\030\030Nvi\021Ic\177\336\222\324\261\365\245P\177\017M\334\307\241V\304*\324\276,Fs\202\266\234\333a\034\377\375\341|5N MN\024\010\355\266\257KcmF\223\244\356" > 
(10) 2017/06/06 11:27:49 [client] 11:27:49.870 send ▶ INFO 00a [Client 877641953] Successfully sent request:%!(EXTRA *comm.Message=bigint:<X1:"h\331\342\241\222\213\261\031\nB<\014CO\032BB\035\030T\202\312\215vg$\017\313\246\203\217\311\245\224\373\345A\333\035,K'G\327Rl\267\246T\206wN#;i\351\316Zz\255\204?\324\003!(\026\230$\335d\200\333\222\003\251|\246@\240a\020\314K\277\301\276v\362Z\311h\340dT,w\277i\353\tM\251\242\200\311~\335[\365\005\357\352\377\3310\235\230w\325t 4\\\370\276\032\002\205\316\336\037\326I\007\353\233\313\277'\361%\347C\334\336\217\352\024\370b\016Jy\273\346\177\351f~\243{\377\234\"'\236p\244\315]\332\3761\022\375\303'\333Z;|\017\346\343\331\020\301\366\220\005\310\317D\226\374\335\2547\334b-\271r\333\355u\214\332\272h\252$`\027I\345\376\302\200u]\362C]l\327\035)\300\370\224\301\312\321K\241\314\325\265\234\270z\234\"\035C\303AE,#Q:\311\321" > )
(11) 2017/06/06 11:27:49 [client] 11:27:49.870 receive ▶ INFO 00b [Client 877641953] Received response from the stream: empty:<> 
(12) 2017/06/06 11:27:49 [client] 11:27:49.870 send ▶ INFO 00c [Client 877641953] Successfully sent request:%!(EXTRA *comm.Message=pedersen_decommitment:<X:"\0079\214\331" R:"r\002 \343S\261M\2532\344\300\362\224k\316\374\277\020~\302\016\022<C\326\242\220\210m\247\016+" > )
(13) 2017/06/06 11:27:49 [client] 11:27:49.872 receive ▶ INFO 00d [Client 877641953] Received response from the stream: status:<Success:true > 
(14) 2017/06/06 11:27:49 [client] 11:27:49.872 ExecuteProtocol ▶ NOTI 00e [Client 877641953] SUCCESS, closing stream
(15) 2017/06/06 11:27:49 [client] 11:27:49.872 runClients ▶ NOTI 00f Time: 0.004637867 seconds
```

Lines 1-6 indicate the undergoing initialization procedure for the purpose of communication with the emmy server (instantiating appropriate client structure for excecution of the chosen protocol, retrieving connection to the server and retrieving a stream object that is used to pass messages to and from the server). Line 7 indicates the beginning of the chosen protocol. Lines 8-13 demonstrate the communication within the protocol, e.g. you can see the payload being sent to and received from the emmy server. Line 14 indicates that the protocol has successfully finished. The last line reports the total time required to execute the protocol - if we run several clients (either sequentially or concurrently), it prints the total time required for all the clients to finish.

## Run full examples 
For convenience, you don't have to run `emmy server` and `emmy client` separately. If you just want to see the execution of a chosen protocol for demonstration purposes, you can use exactly the same flags as in `emmy client`, but run the `emmy example` program instead. This will start the emmy server before running the clients and all the output (both server's and clients') will be logged to the same terminal window.

Here's an example for running `emmy example`, along with a part of its output:

```
$ emmy example -protocol schnorr -n 2 --concurrent

2017/06/06 11:49:39 [client] 11:49:39.084 runClients ▶ INFO 001 Running client #0
2017/06/06 11:49:39 [client] 11:49:39.084 runClients ▶ INFO 002 Running client #1
2017/06/06 11:49:39 [client] 11:49:39.084 NewProtocolClient ▶ DEBU 003 Creating client [SchemaType = SCHNORR][SchemaVariant = SIGMA]
2017/06/06 11:49:39 [client] 11:49:39.084 getConnection ▶ DEBU 004 Getting the connection
2017/06/06 11:49:39 [server] 11:49:39.084 startEmmyServer ▶ INFO 006 Registering services
2017/06/06 11:49:39 [client] 11:49:39.084 NewProtocolClient ▶ DEBU 005 Creating client [SchemaType = SCHNORR][SchemaVariant = SIGMA]
2017/06/06 11:49:39 [client] 11:49:39.084 getConnection ▶ DEBU 008 Getting the connection
2017/06/06 11:49:39 [server] 11:49:39.084 NewProtocolServer ▶ INFO 007 Instantiating new protocol server
2017/06/06 11:49:39 [server] 11:49:39.084 startEmmyServer ▶ INFO 009 Emmy server listening for connections on port 7007
2017/06/06 11:49:39 [client] 11:49:39.085 NewProtocolClient ▶ DEBU 00a Creating the client
2017/06/06 11:49:39 [client] 11:49:39.085 NewProtocolClient ▶ DEBU 00b Creating the client
2017/06/06 11:49:39 [client] 11:49:39.085 getStream ▶ DEBU 00c Getting the stream
2017/06/06 11:49:39 [client] 11:49:39.085 getStream ▶ DEBU 00d Getting the stream
2017/06/06 11:49:39 [client] 11:49:39.085 NewProtocolClient ▶ INFO 00e NewProtocol client spawned (1203664614)
2017/06/06 11:49:39 [client] 11:49:39.085 ExecuteProtocol ▶ INFO 00f Starting client [1203664614] SCHNORR (SIGMA)
2017/06/06 11:49:39 [server] 11:49:39.085 Run ▶ INFO 010 Starting new RPC
2017/06/06 11:49:39 [server] 11:49:39.085 Run ▶ INFO 011 Starting new RPC

...
```

## TLS support
Communication channel between emmy clients and emmy server is secure, as it enforces the usage of TLS. TLS is used to encrypt communication and to ensure emmy server's authenticity.

By default, the server will attempt to use the private key and certificate in `test/testdata` directory. The provided certificate is self-signed, and therefore the clients can use it as the CA certificate (e.g. certificate of the entity that issued server's certificate) which they have to provide in order to authenticate the server.
 >**Important note:** You should never use the private key and certificate that comes with this repository when running emmy in production. These are meant *for testing and development purposes only*.

In a real world setting, the client needs to keep a copy of the CA certificate which issued server's certificate. When the server presents its certificate to the client, the client uses CA's certificate to check the validity of server's certifiacate.

To control keys and certificates used for TLS, emmy CLI programs use several flags. In addition to those already presented in this document, `emmy server` supports the following flags:

* `--cert` which expects the path to server's certificate in PEM format, 
* `--key` which expects the path to server's private key file.

The same flags can be used with `emmy example` program. If they are omitted, files in `test/testdata` directory are used.

On the other hand, we can provide `emmy client` with the `--caCert` flag, which expects the certificate of the CA that issued emmy server's certificate (in PEM format). Again, if this flag is omitted, the certificate in `test/testdata` directory is used.


# Currently supported crypto primitives

Currently supported crypto primitives with fully implemented communication layer (e.g. client-server communication via gRPC) are listed in the tables below. Note that the ones not ticked are also implemented, but not from communication perspective.

>**Note**: EC = Elliptic Curve, ZKP = Zero Knowledge Proof, ZKPOK = Zero Knowledge Proof Of Knowledge

| Primitives |
| ----- |
| [✓] Schnorr protocol [5] (sigma protocol can be turned into ZKP and ZKPOK) |
| [✓] Schnorr protocol EC (sigma protocol can be turned into ZKP and ZKPOK) |
| [✓] Pedersen commitments |
| [✓] Pedersen commitments EC |
| [✓] ZKP of quadratic residuosity [6] |
| [✓] ZKP of quadratic nonresiduosity [6] |
| [✓] Chaump-Pedersen for proving dlog equality [7] | 
| [✓] DLog Equality Blinded Transcript [4] | 
| [✓] Pseudonym system [4] |
| [✓] Camenisch-Shoup verifiable encryption (cspaillier) [1] |
| [✗] Camenisch-Lysyanskaya signature [2] |
| [✗] Shamir's secret sharing scheme |

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