package socks5

import (
	"fmt"
	"net"
)

type Error struct {
	Err     error
	Conn    net.Conn
	Request *Request
}

func wrapError(err error, conn net.Conn, req *Request) *Error {
	return &Error{
		Err:     err,
		Conn:    conn,
		Request: req,
	}
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s -> %s: %s",
		e.Conn.RemoteAddr(),
		e.Conn.LocalAddr(),
		e.Err,
	)
}

func (e *Error) Unwrap() error {
	return e.Err
}
