# Emmy - development

## Source code formatting
All contributions to *emmy* library should conform to source formatting enforced by [goimports](https://godoc.org/golang.org/x/tools/cmd/goimports).
Please install *goimports* and configure your source code editor to automatically run it on every file save.

## To compile .proto files

Go into the root project folder and execute:

```bash
$ protoc -I protobuf/ protobuf/messages.proto protobuf/services.proto protobuf/enums.proto --go_out=plugins=grpc:protobuf
```
