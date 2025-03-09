package jwt_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/AntoninoAdornetto/go-jwt"
)

var (
	secret = []byte("secretkey")

	testData = []struct {
		token        string
		secret       []byte
		header       jwt.Header
		claims       jwt.RegisteredClaims
		customClaims jwt.MP
	}{
		{
			token:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjJ9.TgXUUERJYwoco064rOXbsxaB-glEo8UR8z_qcKrj0Qo",
			secret: secret,
			header: jwt.Header{
				Alg: jwt.SIGNING_ALG_HS256,
				Typ: "JWT",
			},
			claims: jwt.RegisteredClaims{
				Iat: 1516239022,
			},
		},
		{
			token:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJtb2dnZWQiLCJleHAiOjE1MTYyMzkwMjIsImlhdCI6MTUxNjIzODg2NSwiaXNzIjoibW9nZ2VkIn0.pWSzwu7BqpvJoYArChSbcL8piF5MEDeGMfmWjCXBa3Y",
			secret: secret,
			header: jwt.Header{
				Alg: jwt.SIGNING_ALG_HS256,
				Typ: "JWT",
			},
			claims: jwt.RegisteredClaims{
				Aud: "mogged",
				Exp: 1516239022,
				Iat: 1516238865,
				Iss: "mogged",
			},
		},
		{
			token:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJtb2dnZWQiLCJleHAiOjE1MTYyMzkwMjIsImlhdCI6MTUxNjIzODg2NSwicm9sZSI6ImFkbWluIn0.B3_BtWGzTv7aa4TFVaATVEOejOOOT4jRVBVoUEoPrJk",
			secret: secret,
			header: jwt.Header{
				Alg: jwt.SIGNING_ALG_HS256,
				Typ: "JWT",
			},
			customClaims: jwt.MP{
				"aud":  "mogged",
				"exp":  1516239022,
				"iat":  1516238865,
				"role": "admin",
			},
		},
	}
)

func TestSignRegisteredClaims(t *testing.T) {
	testCases := []struct {
		name      string
		index     int
		shouldErr bool
	}{
		{
			name:      "creates the correct token using a single standard/registered claim field",
			index:     0,
			shouldErr: false,
		},
		{
			name:      "creates the correct token using multiple standard/registered claim fields",
			index:     1,
			shouldErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := testData[tc.index]
			jwt, err := jwt.New[jwt.RegisteredClaims](data.header.Alg, data.secret)
			assertError(t, false, err)

			token, err := jwt.Sign(data.claims)
			assertError(t, tc.shouldErr, err)

			if strings.Compare(data.token, token) != 0 {
				t.Logf("expected: [%s]\n", data.token)
				t.Logf("got:      [%s]\n", token)
				t.FailNow()
			}
		})
	}
}

func TestSignCustomClaims(t *testing.T) {
	testCases := []struct {
		name      string
		index     int
		shouldErr bool
	}{
		{
			name:      "creates the correct token using a mix of standard and custom claims",
			index:     2,
			shouldErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := testData[tc.index]
			jwt, err := jwt.New[jwt.MP](data.header.Alg, data.secret)
			assertError(t, false, err)

			token, err := jwt.Sign(data.customClaims)
			assertError(t, tc.shouldErr, err)

			if strings.Compare(data.token, token) != 0 {
				t.Logf("expected: [%s]\n", data.token)
				t.Logf("got:      [%s]\n", token)
				t.FailNow()
			}
		})
	}
}

func TestParseStandardClaims(t *testing.T) {
	testCases := []struct {
		name      string
		index     int
		shouldErr bool
	}{
		{
			name:  "parses a token to the correct header and claims",
			index: 0,
		},
		{
			name:  "parses a token to the correct header and claims",
			index: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := testData[tc.index]
			expectedHeader := data.header
			expectedClaims := data.claims

			actual, err := jwt.Parse(
				data.token,
				data.header.Alg,
				data.secret,
				jwt.RegisteredClaims{},
			)
			assertError(t, tc.shouldErr, err)

			if !reflect.DeepEqual(expectedHeader, actual.Header) {
				t.Logf("expected header to be : [%v]\n", expectedHeader)
				t.Logf("got                   : [%v]\n", actual.Header)
				t.FailNow()
			}

			if !reflect.DeepEqual(expectedClaims, actual.Claims) {
				t.Logf("expected claims to be : [%v]\n", expectedClaims)
				t.Logf("got                   : [%v]\n", actual.Claims)
				t.FailNow()
			}
		})
	}
}

// func TestParseCustomClaims(t *testing.T) {
// 	testCases := []struct {
// 		name      string
// 		index     int
// 		shouldErr bool
// 	}{
// 		{
// 			name:  "parses a token to the correct header and claims",
// 			index: 2,
// 		},
// 	}
//
// 	for _, tc := range testCases {
// 		t.Run(tc.name, func(t *testing.T) {
// 			data := testData[tc.index]
// 			expectedHeader := data.header
// 			expectedClaims := data.customClaims
//
// 			actual, err := jwt.Parse(
// 				data.token,
// 				data.header.Alg,
// 				data.secret,
// 				jwt.MP{},
// 			)
// 			assertError(t, tc.shouldErr, err)
//
// 			if !reflect.DeepEqual(expectedHeader, actual.Header) {
// 				t.Logf("expected header to be : [%v]\n", expectedHeader)
// 				t.Logf("got                   : [%v]\n", actual.Header)
// 				t.FailNow()
// 			}
//
// 			if !reflect.DeepEqual(expectedClaims, actual.Claims) {
// 				t.Logf("expected claims to be : [%v]\n", expectedClaims)
// 				t.Logf("got                   : [%v]\n", actual.Claims)
// 				t.FailNow()
// 			}
// 		})
// 	}
// }

func assertError(t *testing.T, shouldErr bool, err error) {
	if shouldErr && err == nil {
		t.Fatalf("expected an error but got nil")
	}

	if !shouldErr && err != nil {
		t.Fatalf("expected err to be nil but got [%s]", err.Error())
	}
}
