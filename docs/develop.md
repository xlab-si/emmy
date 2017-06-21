# Emmy - development

## To compile .proto files

Go into the root project folder and execute:

```
protoc -I protobuf/ protobuf/msgs.proto --go_out=plugins=grpc:protobuf
```
