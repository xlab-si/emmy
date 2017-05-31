package errors

import "errors"

var (
	ErrInvalidSchema  = errors.New("Invalid SchemaType field")
	ErrInvalidVariant = errors.New("Invalid SchemaVariant field")
)
