# Emmy - development

To speed up frequent development tasks and preparation of development environment, this 
repository comes with a *Makefile* and a *docker-compose.yml* file. You can use
* **Makefile** to install and run useful development tools, while
* **docker-compose.yml** can be used to quickly prepare development environment.

## Using Makefile
When using Makefile for the first time, you should run `make setup`. This will install or update 
go tools like [gometalinter](https://github.com/alecthomas/gometalinter) that you *should* learn 
to use on a regular basis. You should re-run `make setup` once in a while to keep these packages 
up-to-date.

Below we provide a brief description of the Makefile's targets, how and when to use them and how 
they can aid the development.

* `make` or `make install` will compile all the packages and produce `emmy` binary with `server` 
and 
`client` CLI commands.
* `make test` will compile and run tests for all the packages and report test coverage.
* `make fmt` will list the files whose formating does not conform to that of *goimports*, and fix 
their formatting. See [Source code formatting](#source-code-formatting).
* `make lint` will run *gometalinter* and display warnings from chosen linters for all go source 
files in this repository except the auto-generated ones .
* `make proto` will run *protoc* compiler in order to re-generate the protobuffer source code 
from proto definitions in the protobuf package. See [Updating protocol buffers](#updating-protocol-buffers).
* `make android` will generate Android archive that can be used to invoke compatible emmy clients
 from an Android application. See [Mobile clients](#mobile-clients).
* `make clean` will remove the files produced by `make android` command.
* `make run` will rebuild and start all the services defined in the `docker-compose.yml` file 
(currently these include emmy server and redis database instance). To have more control over what
 services are started and how, you should consider running `docker-compose` and `docker` commands
  directly - without `make`. For more details please see [Using 
 dockerized Emmy server and redis for development](#using-dockerized-emmy-server-and-redis-for-development).

## Source code formatting
All contributions to *emmy* library should conform to source formatting enforced by [goimports](https://godoc.org/golang.org/x/tools/cmd/goimports).
Please install *goimports* and configure your source code editor to automatically run it on every
 file save. 
 
 Alternatively, you can manually run `make fmt` before submitting a PR. This command will first 
 list the files whose formatting does not conform to *goimports* formatting, and then fix the 
 formatting of all go source files in the repository.  

## Updating protocol buffers
Emmy uses protocol buffers for communication. Definitions of services, RPCs and payloads can be 
found in **.proto* files of the `protobuf` package. We need these definitions and [protoc 
compiler](https://developers
.google.com/protocol-buffers/docs/downloads) in order to obtain appropriate go source files 
with definition of types, functions and interfaces that we are able to import from other packages
 later on.

If definitions in *.proto* files changed, we need to re-generate the source code with *protoc* 
compiler. This means we have to execute the following command from the root of the repository:

```bash
$ protoc -I protobuf/ protobuf/messages.proto protobuf/services.proto protobuf/enums.proto --go_out=plugins=grpc:protobuf
```
Alternatively, you can run `make proto` to re-generate the same files.

# Using dockerized Emmy server and redis for development
For testing and ease of development this repository comes with a *Dockerfile* that you can use to 
spin up an instance of emmy server. 

In addition, we provide a *docker-compose.yml* file you can use to start both emmy server as well as
a redis database to hold registration keys. Note that registration keys need to exist in redis 
beforehand; emmy server only checks for their existence, while a separate entity needs to insert
them into redis (either you put them there manually, or some third party application has to). The
example below shows how a sample registration key can be inserted into the dockerized instance of
the redis database:

````bash
$ docker exec -it emmy-redis redis-cli set testRegKey abcdef;
OK
````
In the command above *emmy-redis* is the name of the redis container (as specified in the
*docker-compose.yml* file), while *redis-cli set testRegKey abcdef* is the command that will be executed
from within the redis container. The result of this command is insertion of a key *testRegKey* with the
value *abcdef*, that has no expiration time set. Note that the current version of emmy server 
only checks the presence of a specific key (in this case *testRegKey*) and does not care about 
the corresponding value.

By default, emmy server will be started in debug mode, but you can modify `emmy-server` service in the
*docker-compose.yml* and provide your own `command` to override the emmy server startup command.

To (re)build and start both emmy server and redis, run:
````bash
$ docker-compose up --build
````
> This is equivalent to running `make run`

Or, if you just want emmy server without redis, you can run:
````bash
$ docker-compose up emmy-server
````
This will use the existing image of the emmy server to start the container, if one exists. 
Otherwise the image will not be rebuilt.

# Mobile clients
Emmy comes with compatibility layer that allows us to re-use some of the library's 
functionality on mobile clients. Currently, we support running **pseudonym system (both modular and
 EC arithmetic variants)** on mobile devices. In order for emmy to run on mobile clients, we're 
 using Go's standard [gomobile](https://golang.org/wiki/Mobile) tool for generation of language 
 bindings (Java or Objective C) for mobile platforms. Note that due to restrictions on the types 
 that can be accessed from mobile application code, only a minimal set of emmy client's 
 functionality is exposed to the mobile application.
 
 > Although the *gomobile* tool imposes the same type restrictions to both Android and iOS 
 platforms, so far mobile clients were only tested on Android platform.  
 
 ## Generating language bindings for mobile clients

First, you will need [gomobile](https://golang.org/wiki/Mobile). To install it, run:
```bash
$ go get -u golang.org/x/mobile/cmd/gomobile
$ gomobile init
```

To generate bindings for an Android application, run:

```bash
$ gomobile bind -v -o emmy.aar github.com/xlab-si/emmy/client/compatibility
``` 

This will produce an Android archive (.aar file) named *emmy.aar* that you can add as a module in 
your Android application. Then, you will be able to import exposed classes from the Java code
 of Android application by importing a subset of Java package *compatibility*. 
 
Please refer to 
 [compatibility package documentation](../client/compatibility/doc.go) for more details.
