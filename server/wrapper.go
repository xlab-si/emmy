package main

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"io"
)

type Server struct{}

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
		logger.Warning("EOF error")
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

		reqSchemaType := req.GetSchema()
		reqSchemaVariant := req.GetSchemaVariant()
		reqSchemaTypeStr := pb.SchemaType_name[int32(reqSchemaType)]
		reqSchemaVariantStr := pb.SchemaVariant_name[int32(reqSchemaVariant)]
		reqClientId := req.GetClientId()
		logger.Notice("Client [", reqClientId, "] requested", reqSchemaTypeStr, "variant", reqSchemaVariantStr)

		// Convert Sigma, ZKP or ZKPOK protocol type to a common type
		protocolType := getProtocolType(reqSchemaVariant)

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
			logger.Errorf("The requested protocol (%v %v) is currently unsupported.", reqSchemaTypeStr, reqSchemaVariantStr)
		}
		//case *pb.PedersenFirst:
		// Schnorr ZKP/ZKP
		/*default:
			logger.Info("Received intermediate request", req)
		}*/

	}

	logger.Info("RPC done")

	return nil
}

func getProtocolType(variant pb.SchemaVariant) common.ProtocolType {
	switch variant {
	case pb.SchemaVariant_ZKP:
		return common.ZKP
	case pb.SchemaVariant_ZKPOK:
		return common.ZKPOK
	default:
		return common.Sigma
	}
}
