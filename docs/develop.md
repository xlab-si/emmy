# Emmy - development

## To compile .proto files

Go into the root project folder and execute:

```
protoc -I comm/pro/ comm/pro/msgs.proto --go_out=plugins=grpc:comm/pro
```
