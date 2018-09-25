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
	"fmt"
	"os"
	"testing"

	"io/ioutil"

	"flag"

	"time"

	"github.com/go-redis/redis"
	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/crypto/cl"
	"github.com/xlab-si/emmy/log"
	"github.com/xlab-si/emmy/server"
	"google.golang.org/grpc"
)

var testGrpcServerEndpoint = "localhost:7008"

// testGrpcClientConn is re-used for all the test clients
var testGrpcClientConn *grpc.ClientConn

var testRedis = flag.Bool(
	"db",
	false,
	"whether to use a real redis server in integration test",
)

// TestMain is run implicitly and only once, before any of the tests defined in this file run.
// It sets up a test gRPC server and establishes connection to the server. This gRPC client
// connection is then re-used in all the tests to reduce overhead.
// Once all the tests run, we close the connection to the server and stop the server.
//
// When this package is tested with -db flag, the test will attempt to connect to a redis
// server on localhost:6379.
// In the absence of -db flag, mock implementations will be used.
func TestMain(m *testing.M) {
	flag.Parse()

	var regKeyDB server.RegistrationManager
	testRegKeys := []string{"testRegKey1", "testRegKey2", "testRegKey3", "testRegKey4"}

	var recDB cl.ReceiverRecordManager

	if *testRedis { // use real redis instance
		fmt.Println("Using a redis instance for storage")
		// connect to a redis database
		c := redis.NewClient(&redis.Options{
			Addr: "localhost:6379",
		})
		err := c.Ping().Err()
		if err != nil {
			fmt.Println("unable to connect to test redis instance:", err)
			os.Exit(1)
		}

		// insert test registration keys
		for _, regKey := range testRegKeys {
			err = c.Set(regKey, regKey, time.Minute).Err()
			if err != nil {
				fmt.Println("cannot insert test registration keys to redis:", err)
				os.Exit(1)
			}
		}

		regKeyDB = server.NewRedisClient(c)
		recDB = cl.NewRedisClient(c)
	} else { // use mock storage
		fmt.Println("Using mock storage")
		// prepare mocks
		mock := &mockRegKeyDB{}
		mock.insert(testRegKeys...)
		regKeyDB = mock
		recDB = cl.NewMockRecordManager()
	}

	logger, _ := log.NewStdoutLogger("testServer", log.NOTICE, log.FORMAT_LONG)
	server, err := server.NewServer("testdata/server.pem", "testdata/server.key",
		regKeyDB, recDB, logger)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Configure a custom logger for the client package
	clientLogger, _ := log.NewStdoutLogger("client", log.NOTICE, log.FORMAT_SHORT)
	SetLogger(clientLogger)

	go server.Start(7008)

	// Establish a connection to previously started server
	testCert, err := ioutil.ReadFile("testdata/server.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	testGrpcClientConn, err = GetConnection(NewConnectionConfig(testGrpcServerEndpoint, "",
		testCert, 500))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// At this point all the tests will actually run
	returnCode := m.Run()

	// Cleanup - close connection, stop the server and exit
	server.Teardown()
	testGrpcClientConn.Close()
	os.Exit(returnCode)
}

// TestInvalidStreamGenerationFunction verifies that if clients using streaming RPCs to
// communicate with the server try to open a client stream with an invalid stream generation
// function, the error gets caught.
func TestInvalidStreamGenerationFunction(t *testing.T) {
	// We don't care about which client we instantiate here, or its arguments,
	// since the underlying behavior we're testing is the same for all of them
	c, _ := NewPseudonymsysCAClient(testGrpcClientConn, nil)
	// This is otherwise called implicitly at the beginning of any client's function
	// for running a given cryptographic protocol
	res := c.openStream(c.grpcClient, "InvalidFunc")
	assert.NotNil(t, res, "stream generation function is invalid, error should be produced")
}

// TestConnectionTimeout tests whether timeout of initial connection to the server is reached.
func TestConnectionTimeout(t *testing.T) {
	_, err := GetConnection(NewConnectionConfig("localhost:4321", "",
		nil, 100))
	assert.NotNil(t, err, "there is no emmy server listening on a given address, "+
		"timeout should be reached")
}

// mockRegKeyDB mocks storage of registration keys. It is a
// slice that will hold the keys.
type mockRegKeyDB struct {
	data []string
}

// insert inserts multiple registration keys to mockRegKeyDB,
// skipping the ones that are already present.
func (m *mockRegKeyDB) insert(keys ...string) {
	for _, keyToInsert := range keys {
		alreadyPresent := false
		for _, key := range m.data {
			if key == keyToInsert {
				alreadyPresent = true
				break
			}
		}
		if !alreadyPresent {
			m.data = append(m.data, keyToInsert)
		}
	}
}

// CheckRegistrationKey checks for the presence of registration
// key key, removing it and returning success if it was present.
// If the key is not present in the slice, it returns false.
func (m *mockRegKeyDB) CheckRegistrationKey(key string) (bool, error) {
	for i, regKey := range m.data {
		if key == regKey {
			m.data = append(m.data[:i], m.data[i+1:]...) // remove i
			return true, nil
		}
	}

	return false, nil
}
