package base

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/commitments"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlogproofs"
	"github.com/xlab-si/emmy/encryption"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"io"
	"log"
	"math/big"
	"math/rand"
	"sync"
	"time"
)

var mutex = &sync.Mutex{}
var clientReadMutex = &sync.Mutex{}
var clientWriteMutex = &sync.Mutex{}

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
	Id            int
}

/* To bootstrap a protocol, client must send some value */
type ProtocolParams map[string]big.Int

func getConnection() (*grpc.ClientConn, error) {
	log.Println("Getting the connection")
	serverEndpoint := config.LoadServerEndpoint()
	conn, err := grpc.Dial(serverEndpoint, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Could not connect to server %v (%v)", serverEndpoint, err)
	}
	return conn, err
}

var client pb.ProtocolClient

//var connInstance *grpc.ClientConn
var once sync.Once

/*func getConnection() (*grpc.ClientConn, error) {
	once.Do(func() {
		serverEndpoint := config.LoadServerEndpoint()
		conn, err := grpc.Dial(serverEndpoint, grpc.WithInsecure())
		if err != nil {
			log.Fatalf("Could not connect to server (%v)", err)
			return
		}

		connInstance = conn
		log.Println("*********** CREATED A NEW CLIENT GRPC CONNECTION *********** ")
	})
	return connInstance, nil
}*/

func getStream(client pb.ProtocolClient) (pb.Protocol_RunClient, error) {
	log.Println("Getting the stream")
	mutex.Lock()
	stream, err := client.Run(context.Background())
	mutex.Unlock()

	if err != nil {
		log.Fatalf("Error creating the stream: %v", err)
	}
	return stream, err
}

func getClient(conn *grpc.ClientConn) *pb.ProtocolClient {
	//once.Do(func() {
	log.Println("Getting the client")
	pbClient := pb.NewProtocolClient(conn)
	client = pbClient
	//})

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

	/*This locking solved all my problems...*/
	stream, err := getStream(client)

	if err != nil {
		return nil
	}

	rand.Seed(time.Now().UTC().UnixNano())

	protocolClient := Client{
		id:      rand.Int31(), //params.Id,
		client:  &client,
		conn:    conn,
		stream:  stream,
		schema:  schema,
		variant: variant,
		handler: &ClientHandler{},
	}

	log.Printf("NewProtocol client spawned")
	return &protocolClient
}

func (c *Client) send(msg *pb.Message) error {
	log.Printf("[Client %v] Begin send", c.id)
	log.Printf("[SEND][Client %v] Trying to send message: %v", c.id, msg)
	//clientWriteMutex.Lock()
	err := (c.stream).Send(msg)
	//clientWriteMutex.Unlock()
	//mutex.Unlock()
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
	//clientReadMutex.Lock()
	resp, err := (c.stream).Recv() // <--- for second request, hangs here
	//clientReadMutex.Unlock()
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

// Pass optional parameters? some schemas need it
func (c *Client) ExecuteProtocol(params ProtocolParams) {
	//defer (c.conn).Close()

	/*waitc := make(chan struct{})
	go func() {*/
	schemaType := pb.SchemaType_name[int32(c.schema)]
	schemaVariant := pb.SchemaVariant_name[int32(c.variant)]
	log.Printf("Started client [%v] %v (%v)", c.id, schemaType, schemaVariant)

	//mutex.Lock()

	switch c.schema {
	case pb.SchemaType_PEDERSEN_EC:
		//log.Printf("Implemented")
		//mutex.Lock()
		c.PedersenEC(params["commitVal"])
		//mutex.Unlock()
	default:
		log.Printf("Not implemented yet")
	}
	//mutex.Unlock()

	log.Printf("[Client %v] Finished ExecuteProtocol", c.id)

	/*for {
		//log.Printf("Helo")
	}*/

	//https://groups.google.com/forum/#!searchin/grpc-io/close$20stream$20go%7Csort:relevance/grpc-io/4X2H6-YapT8/tPdUMmBTBAAJ
	/* THIS HAPPENS EVEN WITHOUT CLOSESEND: 2017/05/21 19:40:05 transport: http2Server.HandleStreams failed to read frame:
	ead tcp 127.0.0.1:7007->127.0.0.1:16438: wsarecv: An existing connection was forcibly closed by the remote host.
	*/
	//(c.stream).CloseSend() // if we have this, and concurrent clients, we get handlestreams error
	//(*c.conn).Close()

	//return
	/*}()
	(c.stream).CloseSend()
	<-waitc*/
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

func (c *Client) Finish() {
	(*c.conn).Close()
	log.Println("Closing connection to gRPC server")
}
