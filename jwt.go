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

func (j *JWT[C]) Sign(claims C) (string, error) {
	j.Claims = claims
	unsigned, err := j.signInput()
	if err != nil {
		return "", err
	}

	sig, err := j.Signer.Sign(unsigned)
	if err != nil {
		return "", err
	}

	encodedSig := encode(sig)
	return unsigned + "." + encodedSig, nil
}
func (j *JWT[C]) signInput() (string, error) {
	var err error

	segments := make([]string, 2)
	for i := range segments {
		var jsonEnc []byte

		if i == 0 {
			if jsonEnc, err = json.Marshal(j.Header); err != nil {
				return "", err
			}
		} else {
			if jsonEnc, err = json.Marshal(j.Claims); err != nil {
				return "", err
			}
		}

		segments[i] = encode(jsonEnc)
	}

	return strings.Join(segments, "."), nil
}

func (j *JWT[C]) extract(segments []string) error {
	for i := range 2 {
		dec, err := decode(segments[i])
		if err != nil {
			return err
		}

		if i == 0 {
			if err = json.Unmarshal(dec, &j.Header); err != nil {
				return err
			}
		} else {
			if err = json.Unmarshal(dec, &j.Claims); err != nil {
				return err
			}
		}
	}

	return nil
}

func encode(segment []byte) string {
	return base64.RawURLEncoding.EncodeToString(segment)
}

