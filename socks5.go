package socks5

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"sync"
)

const (
	socks5Version = uint8(5)
)

// Config is used to setup and configure a Server
type Config struct {
	// AuthMethods can be provided to implement custom authentication
	// By default, "auth-less" mode is enabled.
	// For password-based auth use UserPassAuthenticator.
	AuthMethods []Authenticator

	// AuthMethods can be provided to implement custom order of client supported authentication methods
	// If not provided, order is client defined.
	AuthMethodsSort func([]byte) []byte

	// If provided, username/password authentication is enabled,
	// by appending a UserPassAuthenticator to AuthMethods. If not provided,
	// and AUthMethods is nil, then "auth-less" mode is enabled.
	Credentials CredentialStore

	// Resolver can be provided to do custom name resolution.
	// Defaults to DNSResolver if not provided.
	Resolver NameResolver

	// Rules is provided to enable custom logic around permitting
	// various commands. If not provided, PermitAll is used.
	Rules RuleSet

	// Rewriter can be used to transparently rewrite addresses.
	// This is invoked before the RuleSet is invoked.
	// Defaults to NoRewrite.
	Rewriter AddressRewriter

	// BindIP is used for bind or udp associate
	BindIP net.IP

	// ErrorHandler is invoked when an error occurs.
	ErrorHandler func(error)

	// BaseContext optionally specifies a base context for requests.
	// If nil, the context.Background() is used.
	BaseContext func(*Request) context.Context

	// Optional function for dialing out
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Server is reponsible for accepting connections and handling
// the details of the SOCKS5 protocol
type Server struct {
	config      *Config
	authMethods map[uint8]Authenticator

	shutdown chan struct{}
	listener net.Listener
	lock     sync.Mutex
}

// New creates a new Server and potentially returns an error
func New(conf *Config) (*Server, error) {
	// Ensure we have at least one authentication method enabled
	if len(conf.AuthMethods) == 0 {
		if conf.Credentials != nil {
			conf.AuthMethods = []Authenticator{&UserPassAuthenticator{conf.Credentials}}
		} else {
			conf.AuthMethods = []Authenticator{&NoAuthAuthenticator{}}
		}
	}

	// Ensure we have a DNS resolver
	if conf.Resolver == nil {
		conf.Resolver = DNSResolver{}
	}

	// Ensure we have a rule set
	if conf.Rules == nil {
		conf.Rules = PermitAll()
	}

	server := &Server{
		config: conf,

		shutdown: make(chan struct{}),
	}

	server.authMethods = make(map[uint8]Authenticator)

	for _, a := range conf.AuthMethods {
		server.authMethods[a.GetCode()] = a
	}

	return server, nil
}

// ListenAndServe is used to create a listener and serve on it
func (s *Server) ListenAndServe(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}

	s.lock.Lock()
	s.listener = l
	s.lock.Unlock()

	return s.Serve(l)
}

// Serve is used to serve connections from a listener
func (s *Server) Serve(l net.Listener) error {
	conns := make(chan net.Conn)
	errs := make(chan error)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				errs <- err
				return
			}
			conns <- conn
		}
	}()

	for {
		select {
		case conn := <-conns:
			go func() {
				if err := s.ServeConn(conn); err != nil && s.config.ErrorHandler != nil {
					s.config.ErrorHandler(err)
				}
			}()
		case err := <-errs:
			return err
		case <-s.shutdown:
			return nil
		}
	}
}

// Shutdown is used to shutdown the server. It will close the listener and
// wait for all connections to be closed.
func (s *Server) Shutdown() {
	s.lock.Lock()
	defer s.lock.Unlock()
	
	close(s.shutdown)
	if s.listener != nil {
		s.listener.Close()
	}
}

// ServeConn is used to serve a single connection.
func (s *Server) ServeConn(conn net.Conn) error {
	defer conn.Close()
	bufConn := bufio.NewReader(conn)

	// Read the version byte
	version := []byte{0}
	if _, err := bufConn.Read(version); err != nil {
		return wrapError(fmt.Errorf("read version byte: %w", err), conn, nil)
	}

	// Ensure we are compatible
	if version[0] != socks5Version {
		return wrapError(fmt.Errorf("unsupported socks version: %v", version), conn, nil)
	}

	// Authenticate the connection
	authContext, err := s.authenticate(conn, bufConn)
	if err != nil {
		return wrapError(fmt.Errorf("authenticate: %w", err), conn, nil)
	}

	request, err := NewRequest(bufConn)
	if err != nil {
		if err == unrecognizedAddrType {
			if err := sendReply(conn, addrTypeNotSupported, nil); err != nil {
				return wrapError(fmt.Errorf("send reply: %v", err), conn, nil)
			}
		}
		return wrapError(fmt.Errorf("read dst addr: %w", err), conn, nil)
	}
	request.AuthContext = authContext
	if client, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		request.RemoteAddr = &AddrSpec{IP: client.IP, Port: client.Port}
	}

	// Process the client request
	if err := s.handleRequest(request, conn); err != nil {
		return wrapError(fmt.Errorf("handle request: %v", err), conn, request)
	}

	return nil
}
