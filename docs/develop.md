# Emmy - development

## Source code formatting
All contributions to *emmy* library should conform to source formatting enforced by [goimports](https://godoc.org/golang.org/x/tools/cmd/goimports).
Please install *goimports* and configure your source code editor to automatically run it on every file save.

## To compile .proto files

Go into the root project folder and execute:

```bash
$ protoc -I protobuf/ protobuf/messages.proto protobuf/services.proto protobuf/enums.proto --go_out=plugins=grpc:protobuf
```

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
