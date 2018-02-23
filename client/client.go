/*
 * Copyright 2017 XLAB d.o.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package client

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"time"

	"reflect"

	"github.com/xlab-si/emmy/log"
	pb "github.com/xlab-si/emmy/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var logger log.Logger

// init instantiates and configures client logger with default log level.
func init() {
	clientLogger, err := log.NewStdoutLogger("client", log.INFO, log.FORMAT_SHORT)
	if err != nil {
		panic(err)
	}
	logger = clientLogger
}

// GetLogger returns the instance of log.Logger currently configured for this package.
func GetLogger() log.Logger {
	return logger
}

// SetLogger assigns the log.Logger instance passed as argument to the logger of this package.
// This is to support loggers other than log.StdoutLogger, which is set as default in init function.
func SetLogger(lgr log.Logger) {
	logger = lgr
}

// ConnectionConfig holds all the details required for establishing a connection to the server.
type ConnectionConfig struct {
	Endpoint           string // Server's Endpoint
	ServerNameOverride string // When ServerNameOverride != "",
	// server cert's CN will be compared with the provided ServerNameOverride instead of server's
	// hostname
	CACertificate []byte // CA certificate for validating the server
	TimeoutMillis int    // timeout (in millis) for establishing initial connection with the server
}

func NewConnectionConfig(endpoint, serverNameOverride string, certificate []byte,
	timeoutMillis int) *ConnectionConfig {
	return &ConnectionConfig{
		Endpoint:           endpoint,
		ServerNameOverride: serverNameOverride,
		CACertificate:      certificate,
		TimeoutMillis:      timeoutMillis,
	}
}

// GetConnection attempts to return a connection to a gRPC server based on the provided
// configuration of connection details. Note that several clients can be passed the same
// connection, as the gRPC framework is able to multiplex several RPCs on the same connection,
// thus reducing the overhead.
func GetConnection(connConfig *ConnectionConfig) (*grpc.ClientConn, error) {
	logger.Info("Getting the connection")

	var creds credentials.TransportCredentials
	var err error

	// If the client doesn't explicitly provide a CA certificate, build TLS credentials with
	// the hosts' system certificate pool
	if connConfig.CACertificate == nil {
		logger.Warning("######## No CA certificate was provided ########")
		logger.Warning("Host system's certificate pool will be used to validate the server")
		creds, err = getTLSCredentialsFromSysCertPool()
		if err != nil {
			return nil, fmt.Errorf("error creating TLS client credentials: %s", err)
		}
	} else {
		// If the client provided a CA certificate, he can still allow a mismatch in the server's
		// name and server's CN in certificate
		if connConfig.ServerNameOverride != "" {
			logger.Warning("######## Skipping server's hostname validation ########")
			logger.Warningf("Expecting to find '%s' in the server certificate's CN",
				connConfig.ServerNameOverride)
		}
		creds, err = getTLSCredentials(connConfig.CACertificate, connConfig.ServerNameOverride)
		if err != nil {
			return nil, fmt.Errorf("error creating TLS client credentials: %s", err)
		}
	}
	dialOptions := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
		grpc.WithTimeout(time.Duration(connConfig.TimeoutMillis) * time.Millisecond),
	}
	conn, err := grpc.Dial(connConfig.Endpoint, dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("could not connect to server %v (%v)", connConfig.Endpoint, err)
	}
	logger.Notice("Established connection to gRPC server")
	return conn, nil
}

type genericClient struct {
	id int32
	pb.ClientStream
}

func newGenericClient() genericClient {
	logger.Debug("Creating genericClient")

	rand.Seed(time.Now().UTC().UnixNano())
	client := genericClient{
		id: rand.Int31(),
	}

	logger.Debugf("New genericClient created (%v)", client.id)
	return client
}

func (c *genericClient) send(msg *pb.Message) error {
	if err := c.Send(msg); err != nil {
		return fmt.Errorf("[client %v] Error sending message: %v", c.id, err)
	}
	logger.Infof("[client %v] Successfully sent request of type %T", c.id, msg.Content)
	logger.Debugf("%+v", msg)

	return nil
}

func (c *genericClient) receive() (*pb.Message, error) {
	resp, err := c.Recv()
	if err == io.EOF {
		return nil, fmt.Errorf("[client %v] EOF error", c.id)
	} else if err != nil {
		return nil, fmt.Errorf("[client %v] An error occurred: %v", c.id, err)
	}
	if resp.ProtocolError != "" {
		return nil, fmt.Errorf(resp.ProtocolError)
	}
	logger.Infof("[client %v] Received response of type %T from the genericClient", c.id, resp.Content)
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

// openStream is a generic function for opening a pb.ClientStream.
// A pb.ClientStream is generated as a result of the function call of the form
// stream, err := grpcClient.streamGenFunc(context.Background()). As we have different
// grpcClients (each generated from its own RPC service), each has its own streamGenFunc(s)
// (generated from the appropriate RPC within the service), it is the caller's responsibility
// to provide appropriate grpcClient and streamGenFunc.
// This function has to be called explicitly at the beginning of the protocol execution function.
func (c *genericClient) openStream(grpcClient interface{}, streamGenFunc string) error {
	// Create structs compatible with reflect package
	client := reflect.ValueOf(grpcClient)                            // we want to call streamGenFunc on this struct
	params := []reflect.Value{reflect.ValueOf(context.Background())} // we want to pass these params to streamGenFunc

	// Safety check for existence of the requested stream generation method on a given grpc client
	f := client.MethodByName(streamGenFunc)
	if !f.IsValid() {
		return fmt.Errorf("stream generation function '%s' not defined for %v", streamGenFunc, reflect.TypeOf(grpcClient))
	}

	// Call the client stream generation function
	res := f.Call(params)

	// First, check if an error occurred during creation of the client stream
	var err error
	if v := res[1].Interface(); v != nil {
		err = v.(error)
	}
	if err != nil {
		return fmt.Errorf("[client %v] Error opening stream: %v", c.id, err)
	}

	// creation of the client stream was successful, make type assertion
	var stream pb.ClientStream
	if v := res[0].Interface(); v != nil {
		stream = v.(pb.ClientStream)
	}

	// assign this client stream to our generic client, so that the stream can be
	// used for communication with the server in subsequent send(), receive() calls
	c.ClientStream = stream
	return nil
}

// closeStream closes the gRPC communication genericClient with the server, indicating the end of
// a protocol execution.
// This function has to be called explicitly at the end of protocol execution function.
// Note that closing the genericClient does not closeStream the corresponding connection to the server,
// as it should be done externally.
func (c *genericClient) closeStream() error {
	if err := c.CloseSend(); err != nil {
		return fmt.Errorf("[client %v] Error closing genericClient: %v", c.id, err)
	}
	return nil
}
