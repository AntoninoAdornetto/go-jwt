package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"hash"
)

const (
	SIGNING_ALG_HS256 = "HS256"
)

// ss = signing string
// sig = signature
type TokenSigner interface {
	Sign(ss string) ([]byte, error)
	Equal(ss string, sig []byte) error
}

func NewTokenSigner(alg string, key []byte) (TokenSigner, error) {
	switch alg {
	case SIGNING_ALG_HS256:
		return hs256(key), nil
	default:
		return nil, errors.New("unsupported signing method")
	}
}

type HS256 struct {
	Name   string
	HashFn hash.Hash
}

func hs256(key []byte) *HS256 {
	return &HS256{
		Name:   SIGNING_ALG_HS256,
		HashFn: hmac.New(sha256.New, key),
	}
}

func (s *HS256) Sign(ss string) ([]byte, error) {
	if _, err := s.HashFn.Write([]byte(ss)); err != nil {
		return nil, err
	}
	return s.HashFn.Sum(nil), nil
}

func (s *HS256) Equal(ss string, signature []byte) error {
	target, err := s.Sign(ss)
	if err != nil {
		return err
	}

	if !hmac.Equal(signature, target) {
		return errors.New("invalid signature")
	}

	return nil
}
