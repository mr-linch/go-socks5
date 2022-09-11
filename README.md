go-socks5 [![Build Status](https://travis-ci.org/armon/go-socks5.png)](https://travis-ci.org/armon/go-socks5)
=========

Provides the `socks5` package that implements a [SOCKS5 server](http://en.wikipedia.org/wiki/SOCKS).
SOCKS (Secure Sockets) is used to route traffic between a client and server through
an intermediate proxy layer. This can be used to bypass firewalls or NATs.

Feature
=======

The package has the following features:
* "No Auth" mode
* User/Password authentication
* Support for the CONNECT command
* Rules to do granular filtering of commands
* Custom DNS resolution
* Unit tests

TODO
====

The package still needs the following:
* Support for the BIND command
* Support for the ASSOCIATE command

FORK NOTE
=========

This fork contains a few changes to the original package:
 - Add go modules support
 - Replace `golang.org/x/net/context` with `context`;
 - Add `Password` to payload of `socks5.AuthContext` created by `socks5.UserPassAuthenticator`;
 - Add `RuleSetFunc` implements `RuleSet` interface for simplifying rules creation;
 - Add `CredentialStoreFunc` implements `CredentialStore` interface for simplifying credentials creation;

Example
=======

Below is a simple example of usage

```go
// Create a SOCKS5 server
conf := &socks5.Config{}
server, err := socks5.New(conf)
if err != nil {
  panic(err)
}

// Create SOCKS5 proxy on localhost port 8000
if err := server.ListenAndServe("tcp", "127.0.0.1:8000"); err != nil {
  panic(err)
}
```

