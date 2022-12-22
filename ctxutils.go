package socks5

import (
	"context"
	"net"
)

type ctxKey int

const (
	ctxKeyConn ctxKey = iota
)

func WithClientConn(ctx context.Context, conn conn) context.Context {
	netConn, ok := conn.(net.Conn)
	if !ok {
		return ctx
	}

	return context.WithValue(ctx, ctxKeyConn, netConn)
}

func ClientConnCtx(ctx context.Context) (net.Conn, bool) {
	v := ctx.Value(ctxKeyConn)
	if v == nil {
		return nil, false
	}

	if netConn, ok := v.(net.Conn); ok {
		return netConn, true
	}

	return nil, false
}
