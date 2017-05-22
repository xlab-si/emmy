package base

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/commitments"
	"github.com/xlab-si/emmy/dlogproofs"
	"github.com/xlab-si/emmy/encryption"
	"io"
	"log"
	"sync"
)

var readMutex = &sync.Mutex{}
var writeMutex = &sync.Mutex{}
var streamMutex = &sync.Mutex{}

//var mutex = &sync.Mutex{}

type Server struct {
	handler ServerHandler
	stream  pb.Protocol_RunServer
}

type ServerHandler struct {
	pedersenReciever   *commitments.PedersenReceiver
	pedersenECReciever *commitments.PedersenECReceiver
	schnorrVerifier    *dlogproofs.SchnorrVerifier
	schnorrECVerifier  *dlogproofs.SchnorrECVerifier
	paillierDecryptor  *encryption.CSPaillier
}

func NewProtocolServer() *Server {
	log.Println("Instantiating new protocol server")
	/* At the time of instantiation, we don't yet know which handler or stream to use,
	therefore just return a reference to the empty struct */
	return &Server{}
}

func (s *Server) send(msg *pb.Message) error {
	log.Printf("Begin send")
	//writeMutex.Lock()
	err := s.stream.Send(msg)
	//writeMutex.Unlock()

	if err != nil {
		log.Printf("[SEND] [Server] Error sending message")
		return err
	}
	log.Printf("[SEND] [Server] Successfully sent response:", msg)
	log.Printf("End send")

	return nil
}

func (s *Server) recieve() (*pb.Message, error) {
	log.Printf("Begin receive")
	//readMutex.Lock()
	resp, err := s.stream.Recv()
	//readMutex.Unlock()
	if err == io.EOF {
		log.Printf("[RECIEVE] [Server] EOF error")
		return nil, err
	}
	if err != nil {
		log.Fatalf("[RECIEVE] [Server] An error ocurred: %v", err)
		return nil, err
	}
	log.Printf("[RECIEVE] [Server] Recieved request from the stream", resp)
	log.Printf("End receive")
	return resp, nil
}

func (s *Server) Run(stream pb.Protocol_RunServer) error {
	//streamMutex.Lock()
	s.stream = stream
	//streamMutex.Unlock()
	log.Printf("[Server] ####### New Client connected - 'Run' started in a new server-side goroutine")

	//streamMutex.Lock()

	for {
		log.Println("** Begin new for loop iteration in Run **")
		req, err := s.recieve()
		if err != nil {
			log.Println("Got error when trying to receive from stream")
			//return nil
			//continue
			//req.

			//streamMutex.Unlock()
			//return err <-- if you return here, the server process will close
		}
		//streamMutex.Unlock()
		//req.Content.(type)
		/*if req.Content == pb.Message_Empty {
			log.Println("Got empty message !!!")
		}*/
		switch req.Content.(type) {
		case *pb.Message_Empty:
			log.Println("Got empty message, indicating start of a protocol") // start a new goroutine here

			reqSchemaType := req.GetSchema()
			reqSchemaVariant := req.GetSchemaVariant()
			reqSchemaTypeStr := pb.SchemaType_name[int32(reqSchemaType)]
			reqSchemaVariantStr := pb.SchemaVariant_name[int32(reqSchemaVariant)]
			reqClientId := req.GetClientId()
			log.Println("Client [", reqClientId, "] requested", reqSchemaTypeStr, "variant", reqSchemaVariantStr)

			//streamMutex.Lock()
			switch reqSchemaType {
			case pb.SchemaType_PEDERSEN_EC:
				//return s.PedersenEC()
				//streamMutex.Lock()
				s.PedersenEC()
				//streamMutex.Unlock()
			default:
				log.Println("The requested protocol is currently unsupported.")
			}
		default:
			log.Printf("[Server] Received intermediate request", req)
		}

	}
	//streamMutex.Unlock()

	/* Keeps the stream running, to prevent HandleSterams failed to read frame error */
	/*for {
	}*/

	return nil
}
