package client

import (
	"fmt"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/log"
	pb "github.com/xlab-si/emmy/protobuf"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"io"
	"math/rand"
	"time"
)

var logger = log.ClientLogger

func SetLogLevel(level string) error {
	return logger.SetLevel(level)
}

// GetConnection attempts to return a secure connection to a gRPC server at a given endpoint.
// Note that several clients can be passed the same connection object, as the gRPC framework
// is able to multiplex several RPCs on the same connection, thus reducing the overhead
func GetConnection(serverEndpoint, caCert string, insecure bool) (*grpc.ClientConn, error) {
	logger.Info("Getting the connection")
	timeoutSec := config.LoadTimeout()

	// Notify the end user about security implications when running in insecure mode
	if insecure {
		logger.Warning("######## You requested an **insecure** channel! ########")
		logger.Warning("As a consequence, server's identity will *NOT* be validated!")
		logger.Warning("Please consider using a secure connection instead")
	}

	// Create client TLS credentials
	creds, err := getTLSClientCredentials(caCert, insecure)
	if err != nil {
		return nil, fmt.Errorf("Error creating TLS client credentials: %v", err)
	}

	dialOptions := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
		grpc.WithTimeout(time.Duration(timeoutSec) * time.Second),
	}
	conn, err := grpc.Dial(serverEndpoint, dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("Could not connect to server %v (%v)", serverEndpoint, err)
	}
	logger.Notice("Established connection to gRPC server")
	return conn, nil
}

type genericClient struct {
	id             int32
	protocolClient pb.ProtocolClient
	stream         pb.Protocol_RunClient
}

func newGenericClient(conn *grpc.ClientConn) (*genericClient, error) {
	logger.Debug("Creating the client")
	client := pb.NewProtocolClient(conn)

	rand.Seed(time.Now().UTC().UnixNano())

	genClient := genericClient{
		id:             rand.Int31(),
		protocolClient: client,
	}

	logger.Debugf("New GenericClient spawned (%v)", genClient.id)
	return &genClient, nil
}

func (c *genericClient) send(msg *pb.Message) error {
	if err := c.stream.Send(msg); err != nil {
		return fmt.Errorf("[Client %v] Error sending message: %v", c.id, err)
	}
	logger.Infof("[Client %v] Successfully sent request of type %T", c.id, msg.Content)
	logger.Debugf("%+v", msg)

	return nil
}

func (c *genericClient) receive() (*pb.Message, error) {
	resp, err := c.stream.Recv()
	if err == io.EOF {
		return nil, fmt.Errorf("[Client %v] EOF error", c.id)
	} else if err != nil {
		return nil, fmt.Errorf("[Client %v] An error ocurred: %v", c.id, err)
	}
	if resp.ProtocolError != "" {
		return nil, fmt.Errorf(resp.ProtocolError)
	}
	logger.Infof("[Client %v] Received response of type %T from the stream", c.id, resp.Content)
	logger.Debugf("%+v", resp)

	return resp, nil
}

// getResponseTo sends a message msg to emmy server and retrieves the server's response.
func (c *genericClient) getResponseTo(msg *pb.Message) (*pb.Message, error) {
	if err := c.send(msg); err != nil {
		return nil, err
	}
	return c.receive()
}

// openStream opens the gRPC communication stream with the server prior to actual execution of
// the protocol client.
// This function has to be called explicitly at the beginning of the protocol execution function.
func (c *genericClient) openStream() error {
	stream, err := c.protocolClient.Run(context.Background())
	if err != nil {
		return fmt.Errorf("[Client %v] Error opening stream: %v", c.id, err)
	}

	c.stream = stream
	return nil
}

// closeStream closes the gRPC communication stream with the server, indicating the end of
// a protocol execution.
// This function has to be called explicitly at the end of protocol execution function.
// Note that closing the stream does not close the corresponding connection to the server,
// as it should be done externally.
func (c *genericClient) closeStream() error {
	if err := c.stream.CloseSend(); err != nil {
		return fmt.Errorf("[Client %v] Error closing stream: %v", c.id, err)
	}
	return nil
}
