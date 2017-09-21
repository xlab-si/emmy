package test

import (
	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/client"
	"testing"
)

func TestInsecureConn(t *testing.T) {
	_, err := client.GetConnection(testGrpcServerEndpoint, "", true)
	assert.Nil(t, err, "should finish without errors")
}
