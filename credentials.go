package socks5

// CredentialStore is used to support user/pass authentication
type CredentialStore interface {
	Valid(user, password string) bool
}

type CredentialStoreFunc func(user, password string) bool

func (f CredentialStoreFunc) Valid(user, password string) bool {
	return f(user, password)
}

// StaticCredentials enables using a map directly as a credential store
type StaticCredentials map[string]string

func (s StaticCredentials) Valid(user, password string) bool {
	pass, ok := s[user]
	if !ok {
		return false
	}
	return password == pass
}
