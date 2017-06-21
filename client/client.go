package client

import (
	"fmt"
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/log"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"io"
	"math/rand"
	"time"
)

var logger = log.ClientLogger

type genericClient struct {
	id     int32
	conn   *grpc.ClientConn
	stream pb.Protocol_RunClient
}

func newGenericClient(endpoint string) (*genericClient, error) {
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

	genClient := genericClient{
		id:     rand.Int31(),
		conn:   conn,
		stream: stream,
	}

	logger.Infof("New GenericClient spawned (%v)", genClient.id)
	return &genClient, nil
}

func (c *genericClient) send(msg *pb.Message) error {
	if err := c.stream.Send(msg); err != nil {
		return fmt.Errorf("[Client %v] Error sending message: %v", c.id, err)
	}
	logger.Infof("[Client %v] Successfully sent request:", c.id, msg)

	return nil
}

func (c *genericClient) receive() (*pb.Message, error) {
	resp, err := c.stream.Recv()
	if err == io.EOF {
		return nil, fmt.Errorf("[Client %v] EOF error", c.id)
	} else if err != nil {
		return nil, fmt.Errorf("[Client %v] An error ocurred: %v", c.id, err)
	}
	logger.Infof("[Client %v] Received response from the stream: %v", c.id, resp)
	return resp, nil
}

// getResponseTo sends a message msg to emmy server and retrieves the server's response.
func (c *genericClient) getResponseTo(msg *pb.Message) (*pb.Message, error) {
	if err := c.send(msg); err != nil {
		return nil, err
	}
	return c.receive()
}

// close closes the communication stream and connection to the server.
func (c *genericClient) close() error {
	if err := c.stream.CloseSend(); err != nil {
		return fmt.Errorf("[Client %v] Error closing stream: %v", c.id, err)
	}
	if err := c.conn.Close(); err != nil {
		return fmt.Errorf("[Client %v] Error closing connection: %v", c.id, err)
	}
	return nil
}

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
