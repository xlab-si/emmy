package benchmark

import (
	"fmt"
	"github.com/xlab-si/emmy/log"
	"github.com/xlab-si/emmy/server"
	"os"
	"sync"
	"testing"
)

var testGrpcServerEndpoint = "localhost:7008"

// nClients stands for the number of clients that will be started
var nClients = [4]int{1, 10, 100, 1000}

// benchNames and benchNamesConcurr represent benchmark names outputted in the terminal
var benchNames, benchNamesConcurr [4]string

// TestMain is run implicitly and only once, before any of the benchmarks defined in this file run.
// It prepares benchmark environment by setting up a test gRPC server and stopping it afterwards.
func TestMain(m *testing.M) {
	// Do some initialization - prevent logging as it impatcts benchmark results, and prepare
	// labels for benchmarks.
	prepareBenchmarkTags()
	log.TurnOff()

	// Instantiate emmy server and start it in a seperate goroutine
	server := server.NewProtocolServer()
	go server.Start(7008)

	// Run the benchmarks
	returnCode := m.Run()

	// Cleanup
	server.Teardown()
	os.Exit(returnCode)
}

// prepareBenchmarkTags forms strings representing names of benchmarks that will be outputted
// in the terminal when running 'go test' command.
// For clarity, we differentiate benchmarks involving sequential and concurrent clients.
func prepareBenchmarkTags() {
	for i, v := range nClients {
		benchNames[i] = fmt.Sprintf("N=%d-seq", v)
		benchNamesConcurr[i] = fmt.Sprintf("N=%d-con", v)
	}
}

// benchmarkSequential measures time needed to finish sequentially running function a specified
// number of 'testFunc' function calls.
// It serves as a tool to approximate server-side performance in the absence of concurrency,
// as concurrency is implemented in the server by default.
// We expect 'testFunc' to be a function that creates and runs a protocol client, please refer to
// function definitions in test/commmon.go
func benchmarkSequential(b *testing.B, clients int, testFunc func()) {
	for n := 0; n < b.N; n++ {
		for i := 0; i < clients; i++ {
			testFunc()
		}
	}
}

// benchmarkConcurrent measures protocol execution time needed to finish a specified number of
// concurrent 'testFunc' calls.
// We expect 'testFunc' to be a function that creates and runs a protocol client, please refer to
// function definitions in test/commmon.go
func benchmarkConcurrent(b *testing.B, clients int, testFunc func()) {
	for n := 0; n < b.N; n++ {
		var wg sync.WaitGroup
		for i := 0; i < clients; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				testFunc()
			}()
		}
		wg.Wait()
	}
}
