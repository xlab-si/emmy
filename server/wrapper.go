package server

import (
	"errors"
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/log"
	"io"
)

type Server struct{}

// Custom errors for handling invalid initial messages
var (
	ErrInvalidSchema  = errors.New("Message contains an invalid SchemaType field")
	ErrInvalidVariant = errors.New("Message contains an invalid SchemaVariant field")
)

var logger = log.ServerLogger

func NewProtocolServer() *Server {
	logger.Info("Instantiating new protocol server")
	/* At the time of instantiation, we don't yet know which handler or stream to use,
	therefore just return a reference to the empty struct */
	return &Server{}
}

func (s *Server) send(msg *pb.Message, stream pb.Protocol_RunServer) error {
	err := stream.Send(msg)

	if err != nil {
		logger.Error("Error sending message:", err)
		return err
	}
	logger.Info("Successfully sent response:", msg)

	return nil
}

func (s *Server) recieve(stream pb.Protocol_RunServer) (*pb.Message, error) {
	resp, err := stream.Recv()
	if err == io.EOF {
		return nil, err
	}
	if err != nil {
		logger.Errorf("An error ocurred: %v", err)
		return nil, err
	}
	logger.Info("Recieved request from the stream", resp)

	return resp, nil
}

func (s *Server) Run(stream pb.Protocol_RunServer) error {
	logger.Info("Starting new RPC")

	for {
		req, err := s.recieve(stream)
		if err != nil {
			return nil
		}

		reqClientId := req.GetClientId()
		reqSchemaType := req.GetSchema()
		reqSchemaVariant := req.GetSchemaVariant()

		// Check whether the client requested a valid schema
		reqSchemaTypeStr, schemaValid := pb.SchemaType_name[int32(reqSchemaType)]
		if !schemaValid {
			logger.Errorf("Client [", reqClientId, "] requested invalid schema: %v", reqSchemaType)
			return ErrInvalidSchema
		}

		// Check whether the client requested a valid schema variant
		reqSchemaVariantStr, variantValid := pb.SchemaVariant_name[int32(reqSchemaVariant)]
		if !variantValid {
			logger.Errorf("Client [ %v ] requested invalid schema variant: %v", reqClientId, reqSchemaVariant)
			return ErrInvalidVariant
		}

		logger.Noticef("Client [ %v ] requested schema %v, variant %v", reqClientId, reqSchemaTypeStr, reqSchemaVariantStr)

		// Convert Sigma, ZKP or ZKPOK protocol type to a common type
		protocolType := common.ToProtocolType(reqSchemaVariant)

		dlog := config.LoadPseudonymsysDLog()

		switch reqSchemaType {
		case pb.SchemaType_PEDERSEN_EC:
			s.PedersenEC(stream)
		case pb.SchemaType_PEDERSEN:
			s.Pedersen(dlog, stream)
		case pb.SchemaType_SCHNORR:
			s.Schnorr(req, dlog, protocolType, stream)
		case pb.SchemaType_SCHNORR_EC:
			s.SchnorrEC(req, protocolType, stream)
		default:
			logger.Errorf("The requested protocol (%v %v) is unknown or currently unsupported.", reqSchemaTypeStr, reqSchemaVariantStr)
			return ErrInvalidSchema
		}
	}

	return nil
}
