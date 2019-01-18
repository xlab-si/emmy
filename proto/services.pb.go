// Code generated by protoc-gen-go. DO NOT EDIT.
// source: services.proto

package proto

import proto1 "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import google_protobuf "github.com/golang/protobuf/ptypes/empty"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto1.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for PseudonymSystemCA service

type PseudonymSystemCAClient interface {
	GenerateCertificate(ctx context.Context, opts ...grpc.CallOption) (PseudonymSystemCA_GenerateCertificateClient, error)
	GenerateCertificate_EC(ctx context.Context, opts ...grpc.CallOption) (PseudonymSystemCA_GenerateCertificate_ECClient, error)
}

type pseudonymSystemCAClient struct {
	cc *grpc.ClientConn
}

func NewPseudonymSystemCAClient(cc *grpc.ClientConn) PseudonymSystemCAClient {
	return &pseudonymSystemCAClient{cc}
}

func (c *pseudonymSystemCAClient) GenerateCertificate(ctx context.Context, opts ...grpc.CallOption) (PseudonymSystemCA_GenerateCertificateClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_PseudonymSystemCA_serviceDesc.Streams[0], c.cc, "/proto.PseudonymSystemCA/GenerateCertificate", opts...)
	if err != nil {
		return nil, err
	}
	x := &pseudonymSystemCAGenerateCertificateClient{stream}
	return x, nil
}

type PseudonymSystemCA_GenerateCertificateClient interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ClientStream
}

type pseudonymSystemCAGenerateCertificateClient struct {
	grpc.ClientStream
}

func (x *pseudonymSystemCAGenerateCertificateClient) Send(m *Message) error {
	return x.ClientStream.SendMsg(m)
}

func (x *pseudonymSystemCAGenerateCertificateClient) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *pseudonymSystemCAClient) GenerateCertificate_EC(ctx context.Context, opts ...grpc.CallOption) (PseudonymSystemCA_GenerateCertificate_ECClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_PseudonymSystemCA_serviceDesc.Streams[1], c.cc, "/proto.PseudonymSystemCA/GenerateCertificate_EC", opts...)
	if err != nil {
		return nil, err
	}
	x := &pseudonymSystemCAGenerateCertificate_ECClient{stream}
	return x, nil
}

type PseudonymSystemCA_GenerateCertificate_ECClient interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ClientStream
}

type pseudonymSystemCAGenerateCertificate_ECClient struct {
	grpc.ClientStream
}

func (x *pseudonymSystemCAGenerateCertificate_ECClient) Send(m *Message) error {
	return x.ClientStream.SendMsg(m)
}

func (x *pseudonymSystemCAGenerateCertificate_ECClient) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// Server API for PseudonymSystemCA service

type PseudonymSystemCAServer interface {
	GenerateCertificate(PseudonymSystemCA_GenerateCertificateServer) error
	GenerateCertificate_EC(PseudonymSystemCA_GenerateCertificate_ECServer) error
}

func RegisterPseudonymSystemCAServer(s *grpc.Server, srv PseudonymSystemCAServer) {
	s.RegisterService(&_PseudonymSystemCA_serviceDesc, srv)
}

func _PseudonymSystemCA_GenerateCertificate_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(PseudonymSystemCAServer).GenerateCertificate(&pseudonymSystemCAGenerateCertificateServer{stream})
}

type PseudonymSystemCA_GenerateCertificateServer interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ServerStream
}

type pseudonymSystemCAGenerateCertificateServer struct {
	grpc.ServerStream
}

func (x *pseudonymSystemCAGenerateCertificateServer) Send(m *Message) error {
	return x.ServerStream.SendMsg(m)
}

func (x *pseudonymSystemCAGenerateCertificateServer) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _PseudonymSystemCA_GenerateCertificate_EC_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(PseudonymSystemCAServer).GenerateCertificate_EC(&pseudonymSystemCAGenerateCertificate_ECServer{stream})
}

type PseudonymSystemCA_GenerateCertificate_ECServer interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ServerStream
}

type pseudonymSystemCAGenerateCertificate_ECServer struct {
	grpc.ServerStream
}

func (x *pseudonymSystemCAGenerateCertificate_ECServer) Send(m *Message) error {
	return x.ServerStream.SendMsg(m)
}

func (x *pseudonymSystemCAGenerateCertificate_ECServer) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

var _PseudonymSystemCA_serviceDesc = grpc.ServiceDesc{
	ServiceName: "proto.PseudonymSystemCA",
	HandlerType: (*PseudonymSystemCAServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "GenerateCertificate",
			Handler:       _PseudonymSystemCA_GenerateCertificate_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "GenerateCertificate_EC",
			Handler:       _PseudonymSystemCA_GenerateCertificate_EC_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "services.proto",
}

// Client API for PseudonymSystem service

type PseudonymSystemClient interface {
	GenerateNym(ctx context.Context, opts ...grpc.CallOption) (PseudonymSystem_GenerateNymClient, error)
	GenerateNym_EC(ctx context.Context, opts ...grpc.CallOption) (PseudonymSystem_GenerateNym_ECClient, error)
	ObtainCredential(ctx context.Context, opts ...grpc.CallOption) (PseudonymSystem_ObtainCredentialClient, error)
	ObtainCredential_EC(ctx context.Context, opts ...grpc.CallOption) (PseudonymSystem_ObtainCredential_ECClient, error)
	TransferCredential(ctx context.Context, opts ...grpc.CallOption) (PseudonymSystem_TransferCredentialClient, error)
	TransferCredential_EC(ctx context.Context, opts ...grpc.CallOption) (PseudonymSystem_TransferCredential_ECClient, error)
}

type pseudonymSystemClient struct {
	cc *grpc.ClientConn
}

func NewPseudonymSystemClient(cc *grpc.ClientConn) PseudonymSystemClient {
	return &pseudonymSystemClient{cc}
}

func (c *pseudonymSystemClient) GenerateNym(ctx context.Context, opts ...grpc.CallOption) (PseudonymSystem_GenerateNymClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_PseudonymSystem_serviceDesc.Streams[0], c.cc, "/proto.PseudonymSystem/GenerateNym", opts...)
	if err != nil {
		return nil, err
	}
	x := &pseudonymSystemGenerateNymClient{stream}
	return x, nil
}

type PseudonymSystem_GenerateNymClient interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ClientStream
}

type pseudonymSystemGenerateNymClient struct {
	grpc.ClientStream
}

func (x *pseudonymSystemGenerateNymClient) Send(m *Message) error {
	return x.ClientStream.SendMsg(m)
}

func (x *pseudonymSystemGenerateNymClient) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *pseudonymSystemClient) GenerateNym_EC(ctx context.Context, opts ...grpc.CallOption) (PseudonymSystem_GenerateNym_ECClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_PseudonymSystem_serviceDesc.Streams[1], c.cc, "/proto.PseudonymSystem/GenerateNym_EC", opts...)
	if err != nil {
		return nil, err
	}
	x := &pseudonymSystemGenerateNym_ECClient{stream}
	return x, nil
}

type PseudonymSystem_GenerateNym_ECClient interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ClientStream
}

type pseudonymSystemGenerateNym_ECClient struct {
	grpc.ClientStream
}

func (x *pseudonymSystemGenerateNym_ECClient) Send(m *Message) error {
	return x.ClientStream.SendMsg(m)
}

func (x *pseudonymSystemGenerateNym_ECClient) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *pseudonymSystemClient) ObtainCredential(ctx context.Context, opts ...grpc.CallOption) (PseudonymSystem_ObtainCredentialClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_PseudonymSystem_serviceDesc.Streams[2], c.cc, "/proto.PseudonymSystem/ObtainCredential", opts...)
	if err != nil {
		return nil, err
	}
	x := &pseudonymSystemObtainCredentialClient{stream}
	return x, nil
}

type PseudonymSystem_ObtainCredentialClient interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ClientStream
}

type pseudonymSystemObtainCredentialClient struct {
	grpc.ClientStream
}

func (x *pseudonymSystemObtainCredentialClient) Send(m *Message) error {
	return x.ClientStream.SendMsg(m)
}

func (x *pseudonymSystemObtainCredentialClient) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *pseudonymSystemClient) ObtainCredential_EC(ctx context.Context, opts ...grpc.CallOption) (PseudonymSystem_ObtainCredential_ECClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_PseudonymSystem_serviceDesc.Streams[3], c.cc, "/proto.PseudonymSystem/ObtainCredential_EC", opts...)
	if err != nil {
		return nil, err
	}
	x := &pseudonymSystemObtainCredential_ECClient{stream}
	return x, nil
}

type PseudonymSystem_ObtainCredential_ECClient interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ClientStream
}

type pseudonymSystemObtainCredential_ECClient struct {
	grpc.ClientStream
}

func (x *pseudonymSystemObtainCredential_ECClient) Send(m *Message) error {
	return x.ClientStream.SendMsg(m)
}

func (x *pseudonymSystemObtainCredential_ECClient) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *pseudonymSystemClient) TransferCredential(ctx context.Context, opts ...grpc.CallOption) (PseudonymSystem_TransferCredentialClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_PseudonymSystem_serviceDesc.Streams[4], c.cc, "/proto.PseudonymSystem/TransferCredential", opts...)
	if err != nil {
		return nil, err
	}
	x := &pseudonymSystemTransferCredentialClient{stream}
	return x, nil
}

type PseudonymSystem_TransferCredentialClient interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ClientStream
}

type pseudonymSystemTransferCredentialClient struct {
	grpc.ClientStream
}

func (x *pseudonymSystemTransferCredentialClient) Send(m *Message) error {
	return x.ClientStream.SendMsg(m)
}

func (x *pseudonymSystemTransferCredentialClient) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *pseudonymSystemClient) TransferCredential_EC(ctx context.Context, opts ...grpc.CallOption) (PseudonymSystem_TransferCredential_ECClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_PseudonymSystem_serviceDesc.Streams[5], c.cc, "/proto.PseudonymSystem/TransferCredential_EC", opts...)
	if err != nil {
		return nil, err
	}
	x := &pseudonymSystemTransferCredential_ECClient{stream}
	return x, nil
}

type PseudonymSystem_TransferCredential_ECClient interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ClientStream
}

type pseudonymSystemTransferCredential_ECClient struct {
	grpc.ClientStream
}

func (x *pseudonymSystemTransferCredential_ECClient) Send(m *Message) error {
	return x.ClientStream.SendMsg(m)
}

func (x *pseudonymSystemTransferCredential_ECClient) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// Server API for PseudonymSystem service

type PseudonymSystemServer interface {
	GenerateNym(PseudonymSystem_GenerateNymServer) error
	GenerateNym_EC(PseudonymSystem_GenerateNym_ECServer) error
	ObtainCredential(PseudonymSystem_ObtainCredentialServer) error
	ObtainCredential_EC(PseudonymSystem_ObtainCredential_ECServer) error
	TransferCredential(PseudonymSystem_TransferCredentialServer) error
	TransferCredential_EC(PseudonymSystem_TransferCredential_ECServer) error
}

func RegisterPseudonymSystemServer(s *grpc.Server, srv PseudonymSystemServer) {
	s.RegisterService(&_PseudonymSystem_serviceDesc, srv)
}

func _PseudonymSystem_GenerateNym_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(PseudonymSystemServer).GenerateNym(&pseudonymSystemGenerateNymServer{stream})
}

type PseudonymSystem_GenerateNymServer interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ServerStream
}

type pseudonymSystemGenerateNymServer struct {
	grpc.ServerStream
}

func (x *pseudonymSystemGenerateNymServer) Send(m *Message) error {
	return x.ServerStream.SendMsg(m)
}

func (x *pseudonymSystemGenerateNymServer) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _PseudonymSystem_GenerateNym_EC_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(PseudonymSystemServer).GenerateNym_EC(&pseudonymSystemGenerateNym_ECServer{stream})
}

type PseudonymSystem_GenerateNym_ECServer interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ServerStream
}

type pseudonymSystemGenerateNym_ECServer struct {
	grpc.ServerStream
}

func (x *pseudonymSystemGenerateNym_ECServer) Send(m *Message) error {
	return x.ServerStream.SendMsg(m)
}

func (x *pseudonymSystemGenerateNym_ECServer) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _PseudonymSystem_ObtainCredential_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(PseudonymSystemServer).ObtainCredential(&pseudonymSystemObtainCredentialServer{stream})
}

type PseudonymSystem_ObtainCredentialServer interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ServerStream
}

type pseudonymSystemObtainCredentialServer struct {
	grpc.ServerStream
}

func (x *pseudonymSystemObtainCredentialServer) Send(m *Message) error {
	return x.ServerStream.SendMsg(m)
}

func (x *pseudonymSystemObtainCredentialServer) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _PseudonymSystem_ObtainCredential_EC_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(PseudonymSystemServer).ObtainCredential_EC(&pseudonymSystemObtainCredential_ECServer{stream})
}

type PseudonymSystem_ObtainCredential_ECServer interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ServerStream
}

type pseudonymSystemObtainCredential_ECServer struct {
	grpc.ServerStream
}

func (x *pseudonymSystemObtainCredential_ECServer) Send(m *Message) error {
	return x.ServerStream.SendMsg(m)
}

func (x *pseudonymSystemObtainCredential_ECServer) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _PseudonymSystem_TransferCredential_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(PseudonymSystemServer).TransferCredential(&pseudonymSystemTransferCredentialServer{stream})
}

type PseudonymSystem_TransferCredentialServer interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ServerStream
}

type pseudonymSystemTransferCredentialServer struct {
	grpc.ServerStream
}

func (x *pseudonymSystemTransferCredentialServer) Send(m *Message) error {
	return x.ServerStream.SendMsg(m)
}

func (x *pseudonymSystemTransferCredentialServer) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _PseudonymSystem_TransferCredential_EC_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(PseudonymSystemServer).TransferCredential_EC(&pseudonymSystemTransferCredential_ECServer{stream})
}

type PseudonymSystem_TransferCredential_ECServer interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ServerStream
}

type pseudonymSystemTransferCredential_ECServer struct {
	grpc.ServerStream
}

func (x *pseudonymSystemTransferCredential_ECServer) Send(m *Message) error {
	return x.ServerStream.SendMsg(m)
}

func (x *pseudonymSystemTransferCredential_ECServer) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

var _PseudonymSystem_serviceDesc = grpc.ServiceDesc{
	ServiceName: "proto.PseudonymSystem",
	HandlerType: (*PseudonymSystemServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "GenerateNym",
			Handler:       _PseudonymSystem_GenerateNym_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "GenerateNym_EC",
			Handler:       _PseudonymSystem_GenerateNym_EC_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "ObtainCredential",
			Handler:       _PseudonymSystem_ObtainCredential_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "ObtainCredential_EC",
			Handler:       _PseudonymSystem_ObtainCredential_EC_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "TransferCredential",
			Handler:       _PseudonymSystem_TransferCredential_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "TransferCredential_EC",
			Handler:       _PseudonymSystem_TransferCredential_EC_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "services.proto",
}

// Client API for CLCredentialInfo service

type CLCredentialInfoClient interface {
	GetCredentialStructure(ctx context.Context, in *google_protobuf.Empty, opts ...grpc.CallOption) (*CredentialStructure, error)
	GetAcceptableCredentials(ctx context.Context, in *google_protobuf.Empty, opts ...grpc.CallOption) (*AcceptableCredentials, error)
}

type cLCredentialInfoClient struct {
	cc *grpc.ClientConn
}

func NewCLCredentialInfoClient(cc *grpc.ClientConn) CLCredentialInfoClient {
	return &cLCredentialInfoClient{cc}
}

func (c *cLCredentialInfoClient) GetCredentialStructure(ctx context.Context, in *google_protobuf.Empty, opts ...grpc.CallOption) (*CredentialStructure, error) {
	out := new(CredentialStructure)
	err := grpc.Invoke(ctx, "/proto.CLCredentialInfo/GetCredentialStructure", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cLCredentialInfoClient) GetAcceptableCredentials(ctx context.Context, in *google_protobuf.Empty, opts ...grpc.CallOption) (*AcceptableCredentials, error) {
	out := new(AcceptableCredentials)
	err := grpc.Invoke(ctx, "/proto.CLCredentialInfo/GetAcceptableCredentials", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for CLCredentialInfo service

type CLCredentialInfoServer interface {
	GetCredentialStructure(context.Context, *google_protobuf.Empty) (*CredentialStructure, error)
	GetAcceptableCredentials(context.Context, *google_protobuf.Empty) (*AcceptableCredentials, error)
}

func RegisterCLCredentialInfoServer(s *grpc.Server, srv CLCredentialInfoServer) {
	s.RegisterService(&_CLCredentialInfo_serviceDesc, srv)
}

func _CLCredentialInfo_GetCredentialStructure_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(google_protobuf.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CLCredentialInfoServer).GetCredentialStructure(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.CLCredentialInfo/GetCredentialStructure",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CLCredentialInfoServer).GetCredentialStructure(ctx, req.(*google_protobuf.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _CLCredentialInfo_GetAcceptableCredentials_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(google_protobuf.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CLCredentialInfoServer).GetAcceptableCredentials(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.CLCredentialInfo/GetAcceptableCredentials",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CLCredentialInfoServer).GetAcceptableCredentials(ctx, req.(*google_protobuf.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

var _CLCredentialInfo_serviceDesc = grpc.ServiceDesc{
	ServiceName: "proto.CLCredentialInfo",
	HandlerType: (*CLCredentialInfoServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetCredentialStructure",
			Handler:    _CLCredentialInfo_GetCredentialStructure_Handler,
		},
		{
			MethodName: "GetAcceptableCredentials",
			Handler:    _CLCredentialInfo_GetAcceptableCredentials_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "services.proto",
}

// Client API for CL service

type CLClient interface {
	IssueCredential(ctx context.Context, opts ...grpc.CallOption) (CL_IssueCredentialClient, error)
	UpdateCredential(ctx context.Context, opts ...grpc.CallOption) (CL_UpdateCredentialClient, error)
	ProveCredential(ctx context.Context, opts ...grpc.CallOption) (CL_ProveCredentialClient, error)
}

type cLClient struct {
	cc *grpc.ClientConn
}

func NewCLClient(cc *grpc.ClientConn) CLClient {
	return &cLClient{cc}
}

func (c *cLClient) IssueCredential(ctx context.Context, opts ...grpc.CallOption) (CL_IssueCredentialClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_CL_serviceDesc.Streams[0], c.cc, "/proto.CL/IssueCredential", opts...)
	if err != nil {
		return nil, err
	}
	x := &cLIssueCredentialClient{stream}
	return x, nil
}

type CL_IssueCredentialClient interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ClientStream
}

type cLIssueCredentialClient struct {
	grpc.ClientStream
}

func (x *cLIssueCredentialClient) Send(m *Message) error {
	return x.ClientStream.SendMsg(m)
}

func (x *cLIssueCredentialClient) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *cLClient) UpdateCredential(ctx context.Context, opts ...grpc.CallOption) (CL_UpdateCredentialClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_CL_serviceDesc.Streams[1], c.cc, "/proto.CL/UpdateCredential", opts...)
	if err != nil {
		return nil, err
	}
	x := &cLUpdateCredentialClient{stream}
	return x, nil
}

type CL_UpdateCredentialClient interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ClientStream
}

type cLUpdateCredentialClient struct {
	grpc.ClientStream
}

func (x *cLUpdateCredentialClient) Send(m *Message) error {
	return x.ClientStream.SendMsg(m)
}

func (x *cLUpdateCredentialClient) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *cLClient) ProveCredential(ctx context.Context, opts ...grpc.CallOption) (CL_ProveCredentialClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_CL_serviceDesc.Streams[2], c.cc, "/proto.CL/ProveCredential", opts...)
	if err != nil {
		return nil, err
	}
	x := &cLProveCredentialClient{stream}
	return x, nil
}

type CL_ProveCredentialClient interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ClientStream
}

type cLProveCredentialClient struct {
	grpc.ClientStream
}

func (x *cLProveCredentialClient) Send(m *Message) error {
	return x.ClientStream.SendMsg(m)
}

func (x *cLProveCredentialClient) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// Server API for CL service

type CLServer interface {
	IssueCredential(CL_IssueCredentialServer) error
	UpdateCredential(CL_UpdateCredentialServer) error
	ProveCredential(CL_ProveCredentialServer) error
}

func RegisterCLServer(s *grpc.Server, srv CLServer) {
	s.RegisterService(&_CL_serviceDesc, srv)
}

func _CL_IssueCredential_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(CLServer).IssueCredential(&cLIssueCredentialServer{stream})
}

type CL_IssueCredentialServer interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ServerStream
}

type cLIssueCredentialServer struct {
	grpc.ServerStream
}

func (x *cLIssueCredentialServer) Send(m *Message) error {
	return x.ServerStream.SendMsg(m)
}

func (x *cLIssueCredentialServer) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _CL_UpdateCredential_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(CLServer).UpdateCredential(&cLUpdateCredentialServer{stream})
}

type CL_UpdateCredentialServer interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ServerStream
}

type cLUpdateCredentialServer struct {
	grpc.ServerStream
}

func (x *cLUpdateCredentialServer) Send(m *Message) error {
	return x.ServerStream.SendMsg(m)
}

func (x *cLUpdateCredentialServer) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _CL_ProveCredential_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(CLServer).ProveCredential(&cLProveCredentialServer{stream})
}

type CL_ProveCredentialServer interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ServerStream
}

type cLProveCredentialServer struct {
	grpc.ServerStream
}

func (x *cLProveCredentialServer) Send(m *Message) error {
	return x.ServerStream.SendMsg(m)
}

func (x *cLProveCredentialServer) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

var _CL_serviceDesc = grpc.ServiceDesc{
	ServiceName: "proto.CL",
	HandlerType: (*CLServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "IssueCredential",
			Handler:       _CL_IssueCredential_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "UpdateCredential",
			Handler:       _CL_UpdateCredential_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "ProveCredential",
			Handler:       _CL_ProveCredential_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "services.proto",
}

// Client API for Info service

type InfoClient interface {
	GetServiceInfo(ctx context.Context, in *google_protobuf.Empty, opts ...grpc.CallOption) (*ServiceInfo, error)
}

type infoClient struct {
	cc *grpc.ClientConn
}

func NewInfoClient(cc *grpc.ClientConn) InfoClient {
	return &infoClient{cc}
}

func (c *infoClient) GetServiceInfo(ctx context.Context, in *google_protobuf.Empty, opts ...grpc.CallOption) (*ServiceInfo, error) {
	out := new(ServiceInfo)
	err := grpc.Invoke(ctx, "/proto.Info/GetServiceInfo", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for Info service

type InfoServer interface {
	GetServiceInfo(context.Context, *google_protobuf.Empty) (*ServiceInfo, error)
}

func RegisterInfoServer(s *grpc.Server, srv InfoServer) {
	s.RegisterService(&_Info_serviceDesc, srv)
}

func _Info_GetServiceInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(google_protobuf.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(InfoServer).GetServiceInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.Info/GetServiceInfo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(InfoServer).GetServiceInfo(ctx, req.(*google_protobuf.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

var _Info_serviceDesc = grpc.ServiceDesc{
	ServiceName: "proto.Info",
	HandlerType: (*InfoServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetServiceInfo",
			Handler:    _Info_GetServiceInfo_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "services.proto",
}

func init() { proto1.RegisterFile("services.proto", fileDescriptor1) }

var fileDescriptor1 = []byte{
	// 364 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x93, 0xc1, 0x6a, 0xe2, 0x50,
	0x14, 0x86, 0x13, 0x99, 0x99, 0xc5, 0x19, 0x88, 0xce, 0x95, 0x91, 0x92, 0x76, 0x95, 0x55, 0x57,
	0xb1, 0x44, 0xa8, 0x52, 0xa9, 0x20, 0xc1, 0x8a, 0x60, 0xad, 0xd4, 0x76, 0x5d, 0x92, 0x78, 0x22,
	0x01, 0x93, 0x1b, 0xee, 0x3d, 0x11, 0xf2, 0x16, 0x7d, 0x94, 0xae, 0xfa, 0x5c, 0x7d, 0x84, 0x92,
	0x44, 0x51, 0xac, 0x42, 0xb2, 0x0a, 0xf7, 0xcf, 0xfd, 0xfe, 0x73, 0xf8, 0xf3, 0x07, 0x34, 0x89,
	0x62, 0x13, 0x78, 0x28, 0xcd, 0x58, 0x70, 0xe2, 0xec, 0x77, 0xfe, 0xd0, 0xb5, 0x10, 0xa5, 0x74,
	0x56, 0x3b, 0x59, 0xbf, 0x5c, 0x71, 0xbe, 0x5a, 0x63, 0x3b, 0x3f, 0xb9, 0x89, 0xdf, 0xc6, 0x30,
	0xa6, 0xb4, 0x78, 0x69, 0xbd, 0xab, 0xf0, 0x6f, 0x2e, 0x31, 0x59, 0xf2, 0x28, 0x0d, 0x17, 0xa9,
	0x24, 0x0c, 0xed, 0x21, 0xeb, 0x43, 0x73, 0x8c, 0x11, 0x0a, 0x87, 0xd0, 0x46, 0x41, 0x81, 0x1f,
	0x78, 0x0e, 0x21, 0xd3, 0x0a, 0xc8, 0x7c, 0x2c, 0x06, 0xe8, 0x47, 0x67, 0x43, 0xb9, 0x56, 0x6f,
	0x54, 0x36, 0x80, 0xd6, 0x09, 0xf8, 0x6d, 0x64, 0x97, 0xe3, 0xad, 0xaf, 0x1a, 0xd4, 0x8f, 0x56,
	0x62, 0x1d, 0xf8, 0xbb, 0xf3, 0x9c, 0xa5, 0x61, 0xc9, 0x45, 0x6e, 0x41, 0x3b, 0x80, 0x4a, 0x2f,
	0xc0, 0x7a, 0xd0, 0x78, 0x72, 0xc9, 0x09, 0x22, 0x5b, 0xe0, 0x12, 0x23, 0x0a, 0x9c, 0x75, 0x49,
	0xb2, 0x0f, 0xcd, 0x63, 0xb2, 0xfc, 0xd8, 0x3b, 0x60, 0x2f, 0xc2, 0x89, 0xa4, 0x8f, 0xa2, 0xf2,
	0xe0, 0x7b, 0xf8, 0xff, 0x93, 0x2d, 0x1f, 0xf9, 0xa7, 0x0a, 0x0d, 0x7b, 0xba, 0x27, 0x27, 0x91,
	0xcf, 0xd9, 0x2c, 0xfb, 0x8e, 0xb4, 0x17, 0x17, 0x24, 0x12, 0x8f, 0x12, 0x81, 0xac, 0x65, 0x16,
	0x95, 0x32, 0x77, 0x95, 0x32, 0x47, 0x59, 0xa5, 0x74, 0x7d, 0x6b, 0x7e, 0x82, 0x31, 0x14, 0xf6,
	0x0c, 0x17, 0x63, 0xa4, 0xa1, 0xe7, 0x61, 0x4c, 0x8e, 0xbb, 0xc6, 0xfd, 0x2d, 0x79, 0xd6, 0xf1,
	0x6a, 0xeb, 0x78, 0x92, 0x32, 0x14, 0xeb, 0x43, 0x85, 0x9a, 0x3d, 0x65, 0x5d, 0xa8, 0x4f, 0xa4,
	0x4c, 0xb0, 0x72, 0x6e, 0x3d, 0x68, 0xbc, 0xc6, 0xcb, 0xac, 0xa9, 0x55, 0xc9, 0x2e, 0xd4, 0xe7,
	0x82, 0x6f, 0x2a, 0x83, 0xd6, 0x03, 0xfc, 0xca, 0xe3, 0x1d, 0x64, 0xed, 0xa4, 0x45, 0xf1, 0x0b,
	0xe7, 0xca, 0xb9, 0x10, 0xd8, 0xd6, 0xe7, 0xe0, 0xae, 0xa1, 0xb8, 0x7f, 0x72, 0xb1, 0xf3, 0x1d,
	0x00, 0x00, 0xff, 0xff, 0x96, 0x9e, 0xdc, 0xbe, 0x06, 0x04, 0x00, 0x00,
}
