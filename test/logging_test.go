package test

import (
	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/log"
	"testing"
)

func TestInvalidLogLevel(t *testing.T) {
	_, err := log.NewStdoutLogger("test", "Invalid log level", log.FORMAT_SHORT)
	assert.NotNil(t, err, "should produce an error due to invalid log level")
}

func TestInvalidFormat(t *testing.T) {
	_, err := log.NewStdoutLogger("test", log.INFO, "Invalid format")
	assert.NotNil(t, err, "should produce an error due to invalid log format")
}

func TestWithLogFileThatShouldNotBeCreated(t *testing.T) {
	_, err := log.NewFileLogger("test", "/shouldnotbecreated.txt", log.INFO, log.FORMAT_SHORT)
	assert.NotNil(t, err, "should produce an error because of invalid path")
}
