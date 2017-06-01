package client

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/commitments"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
	"github.com/xlab-si/emmy/encryption"
	"github.com/xlab-si/emmy/errors"
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
	client  *pb.ProtocolClient
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

/* Which type and variant of the schema will client request
schemaTypes => pedersen, pedersen_ec, schnorr, schnorr_ec, cspaillier, cspaillier_ec
schemaVariants => sigma, zkp, zkpok
*/
type ClientParams struct {
	SchemaType    string
	SchemaVariant string
}

/* To bootstrap a protocol, client must send some value */
type ProtocolParams map[string]big.Int

var client pb.ProtocolClient

func getConnection(serverEndpoint string) (*grpc.ClientConn, error) {
	logger.Debug("Getting the connection")
	conn, err := grpc.Dial(serverEndpoint, grpc.WithInsecure())
	if err != nil {
		logger.Criticalf("Could not connect to server %v (%v)", serverEndpoint, err)
	}
	return conn, err
}

func getStream(client pb.ProtocolClient) (pb.Protocol_RunClient, error) {
	logger.Debug("Getting the stream")
	//	mutex.Lock()
	stream, err := client.Run(context.Background())
	//	mutex.Unlock()

	if err != nil {
		logger.Criticalf("Error creating the stream: %v", err)
	}
	return stream, err
}

func getClient(conn *grpc.ClientConn) *pb.ProtocolClient {
	logger.Debug("Getting the client")
	pbClient := pb.NewProtocolClient(conn)
	client = pbClient

	return &client
}

func NewProtocolClient(endpoint string, params *ClientParams) (*Client, error) {
	logger.Debugf(" Trying to create client with [SchemaType = %v][SchemaVariant = %v]", params.SchemaType, params.SchemaVariant)

	schema, success := pb.SchemaType_value[params.SchemaType]
	if !success {
		return nil, errors.ErrInvalidSchema
	}

	variant, success := pb.SchemaVariant_value[params.SchemaVariant]
	if !success && params.SchemaVariant != "" {
		return nil, errors.ErrInvalidVariant
	} else {
		variant = pb.SchemaVariant_value["SIGMA"]
	}

	conn, err := getConnection(endpoint)
	if err != nil {
		return nil, err
	}

	client = *getClient(conn)

	stream, err := getStream(client)

	if err != nil {
		return nil, err
	}

	rand.Seed(time.Now().UTC().UnixNano())

	protocolClient := Client{
		id:      rand.Int31(),
		client:  &client,
		conn:    conn,
		stream:  stream,
		schema:  pb.SchemaType(schema),
		variant: pb.SchemaVariant(variant),
		handler: &ClientHandler{},
	}

	logger.Infof("NewProtocol client spawned (%v)", protocolClient.id)
	return &protocolClient, nil
}

func (c *Client) send(msg *pb.Message) error {
	err := (c.stream).Send(msg)

	if err != nil {
		logger.Error("[Client %v] Error sending message: %v", c.id, err)
		return err
	}
	logger.Infof("[Client %v] Successfully sent request:", c.id, msg)

	return nil
}

func (c *Client) recieve() (*pb.Message, error) {
	resp, err := (c.stream).Recv() // <--- for second request, hangs here

	if err == io.EOF {
		logger.Warning("[Client %v] EOF error", c.id)
		return nil, err
	}
	if err != nil {
		logger.Errorf("[Client %v] An error ocurred: %v", c.id, err)
		return nil, err
	}
	logger.Infof("[Client %v] Recieved response from the stream: %v", c.id, resp)
	return resp, nil
}

func (c *Client) ExecuteProtocol(params ProtocolParams) {
	schemaType := pb.SchemaType_name[int32(c.schema)]
	schemaVariant := pb.SchemaVariant_name[int32(c.variant)]
	variant := common.ToProtocolType(c.variant)

	logger.Infof("Starting client [%v] %v (%v)", c.id, schemaType, schemaVariant)

	ps_dlog := config.LoadPseudonymsysDLog()

	var err error
	//var proved bool

	switch c.schema {
	case pb.SchemaType_PEDERSEN:
		err = c.Pedersen(ps_dlog, params["commitVal"])
	case pb.SchemaType_PEDERSEN_EC:
		err = c.PedersenEC(params["commitVal"])
	case pb.SchemaType_SCHNORR:
		err = c.Schnorr(variant, ps_dlog, params["secret"])
	case pb.SchemaType_SCHNORR_EC:
		ec_dlog := dlog.NewECDLog()
		err = c.SchnorrEC(variant, ec_dlog, params["secret"])
	case pb.SchemaType_CSPAILLIER:
		keyDir := config.LoadKeyDirFromConfig()
		pubKeyPath := filepath.Join(keyDir, "cspaillierpubkey.txt")
		_, err = c.Paillier(pubKeyPath, params["m"], params["label"])
	default:
		logger.Warning("Not implemented yet")
	}

	if err != nil {
		logger.Errorf("[Client %v] FAIL: %v", c.id, err)
	} else {
		logger.Noticef("[Client %v] SUCCESS, closing stream", c.id)
	}

	c.stream.CloseSend()
	//c.conn.Close() // Problems occur with concurrent clients - some are exiting
}

// Regardless of what schema type and variant we want, the initial message
// always contains these fields so that server can initialize its handler accordingly
func (c *Client) getInitialMsg() *pb.Message {
	return &pb.Message{
		ClientId:      c.id,
		Schema:        c.schema,
		SchemaVariant: c.variant,
	}
}
