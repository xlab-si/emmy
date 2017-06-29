package server

import (
	"fmt"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/log"
	pb "github.com/xlab-si/emmy/protobuf"
	"io"
	"path/filepath"
)

var _ pb.ProtocolServer = (*Server)(nil)

type Server struct{}

var logger = log.ServerLogger

func NewProtocolServer() *Server {
	logger.Info("Instantiating new protocol server")
	// At the time of instantiation, we don't yet know which handler or stream to use,
	// therefore just return a reference to the empty struct
	return &Server{}
}

func (s *Server) send(msg *pb.Message, stream pb.Protocol_RunServer) error {
	if err := stream.Send(msg); err != nil {
		return fmt.Errorf("Error sending message:", err)
	}
	logger.Info("Successfully sent response:", msg)

	return nil
}

func (s *Server) receive(stream pb.Protocol_RunServer) (*pb.Message, error) {
	resp, err := stream.Recv()
	if err == io.EOF {
		return nil, err
	} else if err != nil {
		return nil, fmt.Errorf("An error ocurred: %v", err)
	}
	logger.Info("Received request from the stream", resp)
	return resp, nil
}

func (s *Server) Run(stream pb.Protocol_RunServer) error {
	logger.Info("Starting new RPC")

	req, err := s.receive(stream)
	if err != nil {
		return err
	}

	reqClientId := req.ClientId
	reqSchemaType := req.Schema
	reqSchemaVariant := req.SchemaVariant

	// Check whether the client requested a valid schema
	reqSchemaTypeStr, schemaValid := pb.SchemaType_name[int32(reqSchemaType)]
	if !schemaValid {
		return fmt.Errorf("Client [", reqClientId, "] requested invalid schema: %v", reqSchemaType)
	}

	// Check whether the client requested a valid schema variant
	reqSchemaVariantStr, variantValid := pb.SchemaVariant_name[int32(reqSchemaVariant)]
	if !variantValid {
		return fmt.Errorf("Client [ %v ] requested invalid schema variant: %v", reqClientId, reqSchemaVariant)
	}

	logger.Noticef("Client [ %v ] requested schema %v, variant %v", reqClientId, reqSchemaTypeStr, reqSchemaVariantStr)

	// Convert Sigma, ZKP or ZKPOK protocol type to a common type
	protocolType := common.ToProtocolType(reqSchemaVariant)

	switch reqSchemaType {
	case pb.SchemaType_PEDERSEN_EC:
		err = s.PedersenEC(stream)
	case pb.SchemaType_PEDERSEN:
		dlog := config.LoadDLog("pedersen")
		err = s.Pedersen(dlog, stream)
	case pb.SchemaType_SCHNORR:
		dlog := config.LoadDLog("schnorr")
		err = s.Schnorr(req, dlog, protocolType, stream)
	case pb.SchemaType_SCHNORR_EC:
		err = s.SchnorrEC(req, protocolType, stream)
	case pb.SchemaType_CSPAILLIER:
		keyDir := config.LoadKeyDirFromConfig()
		secKeyPath := filepath.Join(keyDir, "cspaillierseckey.txt")
		err = s.CSPaillier(req, secKeyPath, stream)
	case pb.SchemaType_PSEUDONYMSYS_CA:
		err = s.PseudonymsysCA(req, stream)
	case pb.SchemaType_PSEUDONYMSYS_NYM_GEN:
		err = s.PseudonymsysGenerateNym(req, stream)
	case pb.SchemaType_PSEUDONYMSYS_ISSUE_CREDENTIAL:
		err = s.PseudonymsysIssueCredential(req, stream)
	case pb.SchemaType_PSEUDONYMSYS_TRANSFER_CREDENTIAL:
		err = s.PseudonymsysTransferCredential(req, stream)
	}

	if err != nil {
		logger.Notice("Closing RPC due to previous errors")
		return fmt.Errorf("FAIL: %v", err)
	}

	logger.Info("RPC finished successfully")
	return nil
}
