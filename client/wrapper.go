package main

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/commitments"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlogproofs"
	"github.com/xlab-si/emmy/encryption"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"io"
	"math/big"
	"math/rand"
	"time"
)

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
	SchemaVariant string `default:"SIGMA"`
}

/* To bootstrap a protocol, client must send some value */
type ProtocolParams map[string]big.Int

var client pb.ProtocolClient

func getConnection() (*grpc.ClientConn, error) {
	logger.Debug("Getting the connection")
	serverEndpoint := config.LoadServerEndpoint()
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

func NewProtocolClient(params *ClientParams) *Client {
	schema := pb.SchemaType(pb.SchemaType_value[params.SchemaType])
	variant := pb.SchemaVariant(pb.SchemaVariant_value[params.SchemaVariant])

	conn, err := getConnection()
	if err != nil {
		return nil
	}

	client = *getClient(conn)

	stream, err := getStream(client)

	if err != nil {
		return nil
	}

	rand.Seed(time.Now().UTC().UnixNano())

	protocolClient := Client{
		id:      rand.Int31(),
		client:  &client,
		conn:    conn,
		stream:  stream,
		schema:  schema,
		variant: variant,
		handler: &ClientHandler{},
	}

	logger.Info("NewProtocol client spawned (%v)", protocolClient.id)
	return &protocolClient
}

func (c *Client) send(msg *pb.Message) error {
	err := (c.stream).Send(msg)

	if err != nil {
		logger.Error("[Client %v] Error sending message: %v", c.id, err)
		return err
	}
	logger.Info("[Client %v] Successfully sent request:", c.id, msg)

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
	logger.Infof("Starting client [%v] %v (%v)", c.id, schemaType, schemaVariant)

	switch c.schema {
	case pb.SchemaType_PEDERSEN_EC:
		c.PedersenEC(params["commitVal"])
	case pb.SchemaType_PEDERSEN:
		c.Pedersen(params["commitVal"])
	default:
		logger.Warning("Not implemented yet")
	}

	logger.Noticef("[Client %v] Done, closing stream", c.id)

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
