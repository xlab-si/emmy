# Emmy - development

## To compile .proto files

Go into the root project folder and execute:

```bash
$ protoc -I protobuf/ protobuf/messages.proto protobuf/services.proto protobuf/enums.proto --go_out=plugins=grpc:protobuf
```
