package client

import (
	"fmt"
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/commitments"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
	"github.com/xlab-si/emmy/encryption"
	"github.com/xlab-si/emmy/log"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"io"
	"math/big"
	"math/rand"
	"path/filepath"
	"time"
)

var logger = log.ClientLogger

type Client struct {
	id      int32
	conn    *grpc.ClientConn
	client  pb.ProtocolClient
	stream  pb.Protocol_RunClient
	schema  pb.SchemaType // int32
	variant pb.SchemaVariant
	handler *ClientHandler
}

type ClientHandler struct {
	pedersenCommitter   *commitments.PedersenCommitter
	pedersenECCommitter *commitments.PedersenECCommitter
	schnorrProver       *dlogproofs.SchnorrProver
	schnorrECProver     *dlogproofs.SchnorrECProver
	paillierEncryptor   *encryption.CSPaillier
}

// ProtocolParams is a map containing values required to bootstrap
// the chosen protocol.
type ProtocolParams map[string]*big.Int

func getConnection(serverEndpoint string) (*grpc.ClientConn, error) {
	logger.Debug("Getting the connection")
	timeoutSec := config.LoadTimeout()
	dialOptions := []grpc.DialOption{
		grpc.WithInsecure(),
		grpc.WithBlock(),
		grpc.WithTimeout(time.Duration(timeoutSec) * time.Second),
	}
	conn, err := grpc.Dial(serverEndpoint, dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("Could not connect to server %v (%v)", serverEndpoint, err)
	}
	return conn, nil
}

func getStream(client pb.ProtocolClient) (pb.Protocol_RunClient, error) {
	logger.Debug("Getting the stream")
	stream, err := client.Run(context.Background())
	if err != nil {
		return nil, fmt.Errorf("Error creating the stream: %v", err)
	}
	return stream, nil
}

func validateSchema(schemaType pb.SchemaType, schemaVariant pb.SchemaVariant) error {
	if _, success := pb.SchemaType_name[int32(schemaType)]; !success {
		return fmt.Errorf("Invalid SchemaType: %v", schemaType)
	}
	if _, success := pb.SchemaVariant_name[int32(schemaVariant)]; !success {
		return fmt.Errorf("Invalid SchemaVariant: %v", schemaVariant)
	}
	return nil
}

func NewProtocolClient(endpoint string, schemaType pb.SchemaType,
	schemaVariant pb.SchemaVariant) (*Client, error) {
	logger.Debugf("Creating client [SchemaType = %v][SchemaVariant = %v]", schemaType,
		schemaVariant)

	if err := validateSchema(schemaType, schemaVariant); err != nil {
		return nil, err
	}

	conn, err := getConnection(endpoint)
	if err != nil {
		return nil, err
	}

	logger.Debug("Creating the client")
	client := pb.NewProtocolClient(conn)
	stream, err := getStream(client)
	if err != nil {
		return nil, err
	}

	rand.Seed(time.Now().UTC().UnixNano())

	protocolClient := Client{
		id:      rand.Int31(),
		client:  client,
		conn:    conn,
		stream:  stream,
		schema:  schemaType,
		variant: schemaVariant,
		handler: &ClientHandler{},
	}

	logger.Infof("NewProtocol client spawned (%v)", protocolClient.id)
	return &protocolClient, nil
}

func (c *Client) send(msg *pb.Message) error {
	if err := c.stream.Send(msg); err != nil {
		return fmt.Errorf("[Client %v] Error sending message: %v", c.id, err)
	}
	logger.Infof("[Client %v] Successfully sent request:", c.id, msg)

	return nil
}

func (c *Client) receive() (*pb.Message, error) {
	resp, err := c.stream.Recv()
	if err == io.EOF {
		return nil, fmt.Errorf("[Client %v] EOF error", c.id)
	} else if err != nil {
		return nil, fmt.Errorf("[Client %v] An error ocurred: %v", c.id, err)
	}
	logger.Infof("[Client %v] Received response from the stream: %v", c.id, resp)
	return resp, nil
}

// close closes the communication stream and connection to the server.
func (c *Client) close() error {
	if err := c.stream.CloseSend(); err != nil {
		return fmt.Errorf("[Client %v] Error closing stream: %v", c.id, err)
	}
	if err := c.conn.Close(); err != nil {
		return fmt.Errorf("[Client %v] Error closing connection: %v", c.id, err)
	}
	return nil
}

func (c *Client) ExecuteProtocol(params ProtocolParams) {
	schemaType := pb.SchemaType_name[int32(c.schema)]
	schemaVariant := pb.SchemaVariant_name[int32(c.variant)]
	variant := common.ToProtocolType(c.variant)

	logger.Infof("Starting client [%v] %v (%v)", c.id, schemaType, schemaVariant)

	var err error

	switch c.schema {
	case pb.SchemaType_PEDERSEN:
		dlog := config.LoadDLog("pedersen")
		err = c.Pedersen(dlog, params["commitVal"])
	case pb.SchemaType_PEDERSEN_EC:
		err = c.PedersenEC(params["commitVal"])
	case pb.SchemaType_SCHNORR:
		dlog := config.LoadDLog("schnorr")
		err = c.Schnorr(variant, dlog, params["secret"])
	case pb.SchemaType_SCHNORR_EC:
		ec_dlog := dlog.NewECDLog()
		err = c.SchnorrEC(variant, ec_dlog, params["secret"])
	case pb.SchemaType_CSPAILLIER:
		keyDir := config.LoadKeyDirFromConfig()
		pubKeyPath := filepath.Join(keyDir, "cspaillierpubkey.txt")
		_, err = c.CSPaillier(pubKeyPath, params["m"], params["label"])
	default:
		err = fmt.Errorf("Invalid SchemaType: ", c.schema)
	}

	if err != nil {
		logger.Errorf("[Client %v] FAIL: %v", c.id, err)
	} else {
		logger.Noticef("[Client %v] SUCCESS, closing stream", c.id)
	}

	if err = c.close(); err != nil {
		logger.Errorf("%v", err)
	}
}

// getInitialMsg is used to form the first message to be sent from client to server.
// Regardless of what schema type and variant the client wants, the first message
// should always contain these fields so that the server can initialize its
// protocol handler accordingly
func (c *Client) getInitialMsg() *pb.Message {
	return &pb.Message{
		ClientId:      c.id,
		Schema:        c.schema,
		SchemaVariant: c.variant,
	}
}
