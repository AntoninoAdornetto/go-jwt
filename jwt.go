package jwt

type JWT[C RegisteredClaims | MP] struct {
	Claims    C
	Header    Header
	Token     string
	Signer    TokenSigner
	Signature []byte
}

type Header struct {
	Alg string `json:"alg,omitempty"`
	Typ string `json:"typ,omitempty"`
}

type RegisteredClaims struct {
	Aud string `json:"aud,omitempty"` // Audience
	Exp int64  `json:"exp,omitempty"` // Expiration (Numeric Time)
	Iat int64  `json:"iat,omitempty"` // Issued at (Numeric Time)
	Iss string `json:"iss,omitempty"` // Issuer
	Jti string `json:"jti,omitempty"` // JWT ID
	Nbf int64  `json:"nbf,omitempty"` // Not before (Numeric Time)
	Sub string `json:"sub,omitempty"` // Subject
}

type MP map[string]any

func New[C RegisteredClaims | MP](alg string, key []byte) (*JWT[C], error) {
	signer, err := NewTokenSigner(alg, key)
	if err != nil {
		return nil, err
	}

	return &JWT[C]{
		Header: Header{
			Alg: alg,
			Typ: "JWT",
		},
		Signer: signer,
	}, nil
}

