package main

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/commitments"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlogproofs"
	"github.com/xlab-si/emmy/encryption"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"io"
	"log"
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

type clientAPI interface {
	pedersenEC(val big.Int) error
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
	log.Println("Getting the connection")
	serverEndpoint := config.LoadServerEndpoint()
	conn, err := grpc.Dial(serverEndpoint, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Could not connect to server %v (%v)", serverEndpoint, err)
	}
	return conn, err
}

func getStream(client pb.ProtocolClient) (pb.Protocol_RunClient, error) {
	log.Println("Getting the stream")
	//	mutex.Lock()
	stream, err := client.Run(context.Background())
	//	mutex.Unlock()

	if err != nil {
		log.Fatalf("Error creating the stream: %v", err)
	}
	return stream, err
}

func getClient(conn *grpc.ClientConn) *pb.ProtocolClient {
	log.Println("Getting the client")
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

	log.Printf("NewProtocol client spawned (%v)", protocolClient.id)
	return &protocolClient
}

func (c *Client) send(msg *pb.Message) error {
	log.Printf("[Client %v] Begin send", c.id)
	log.Printf("[SEND][Client %v] Trying to send message: %v", c.id, msg)

	err := (c.stream).Send(msg)

	if err != nil {
		log.Printf("[SEND][Client %v] Error sending message: %v", c.id, err)
		return err
	}
	log.Printf("[SEND][Client %v] Successfully sent request:", c.id, msg)
	log.Printf("[Client %v] End send", c.id)
	return nil
}

func (c *Client) recieve() (*pb.Message, error) {
	log.Printf("[Client %v] Begin receive", c.id)
	resp, err := (c.stream).Recv() // <--- for second request, hangs here

	if err == io.EOF {
		log.Printf("[RECIEVE][Client %v] EOF error", c.id)
		return nil, err
	}
	if err != nil {
		log.Fatalf("[RECIEVE][Client %v] An error ocurred: %v", c.id, err)
		return nil, err
	}
	log.Printf("[RECIEVE][Client %v] Recieved response from the stream: %v", c.id, resp)
	log.Printf("[Client %v] End receive", c.id)
	return resp, nil
}

func (c *Client) ExecuteProtocol(params ProtocolParams) {
	schemaType := pb.SchemaType_name[int32(c.schema)]
	schemaVariant := pb.SchemaVariant_name[int32(c.variant)]
	log.Printf("Started client [%v] %v (%v)", c.id, schemaType, schemaVariant)

	(c.handler).pedersenECCommitter = commitments.NewPedersenECCommitter()

	initMsg := &pb.Message{
		ClientId:      c.id,
		Schema:        c.schema,
		SchemaVariant: c.variant,
		Content:       &pb.Message_Empty{&pb.EmptyMsg{}},
	}
	err := c.send(initMsg)
	if err != nil {
		log.Fatalf("[Client %v] ERROR: %v", c.id, err)
		return
	}

	log.Printf("[Client %v] Sent request 1", c.id)

	resp, err := c.recieve()
	if err != nil {
		log.Fatalf("[Client %v] ERROR: %v", c.id, err)
		return
	}

	log.Printf("[Client] Received response 1")

	log.Printf("[Client %v] I GOT THIS IN THE MESSAGE: %v", &c, resp.GetEcGroupElement())
	ecge := common.ToECGroupElement(resp.GetEcGroupElement())
	(c.handler).pedersenECCommitter.SetH(ecge)

	val := params["commitVal"]
	commitment, err := c.handler.pedersenECCommitter.GetCommitMsg(&val)
	if err != nil {
		log.Fatalf("could not generate committment message: %v", err)
	}

	my_ecge := common.ToPbECGroupElement(commitment)
	commitmentMsg := &pb.Message{Content: &pb.Message_EcGroupElement{my_ecge}}

	err = c.send(commitmentMsg)
	if err != nil {
		//return err
		log.Fatalf("[Client] ERROR: %v", err)
	}

	log.Printf("[Client] Sent request 2")

	resp, err = c.recieve()
	if err != nil {
		//return err
		log.Fatalf("[Client] ERROR: %v", err)
	}

	log.Printf("[Client] Received response 2")

	decommitVal, r := c.handler.pedersenECCommitter.GetDecommitMsg()
	decommitment := &pb.PedersenDecommitment{X: decommitVal.Bytes(), R: r.Bytes()}
	decommitMsg := &pb.Message{
		Content: &pb.Message_PedersenDecommitment{decommitment},
	}

	err = c.send(decommitMsg)
	if err != nil {
		return //err
	}
	resp, err = c.recieve()
	if err != nil {
		return //err
	}

	log.Printf("[Client %v] ************ DONE ************", c.id)
	log.Printf("[Client %v] Finished ExecuteProtocol", c.id)

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
