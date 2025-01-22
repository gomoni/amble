package accounts

import (
	"context"
	"errors"
	"fmt"
	"log"

	appJWT "github.com/gomoni/amble/internal/auth/jwt"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go/micro"
	"github.com/nats-io/nkeys"
)

const StatusBadRequest = "400"

type Decoder interface {
	Decode(string) (appJWT.Claims, error)
}

type Service struct {
	accounts      Accounts
	xKeyPair      nkeys.KeyPair
	issuerKeyPair nkeys.KeyPair
	decoder       Decoder
}

func NewService(xkey nkeys.KeyPair, issuer nkeys.KeyPair, accounts Accounts, decoder Decoder) (Service, error) {
	var svc Service
	if xkey == nil {
		return svc, errors.New("xkey must not be nil")
	}
	public, err := issuer.PublicKey()
	if err != nil {
		return svc, err
	}
	if !nkeys.IsValidPublicAccountKey(public) {
		return svc, errors.New("Invalid curve key")
	}
	return Service{
		xKeyPair:      xkey,
		issuerKeyPair: issuer,
		accounts:      accounts,
		decoder:       decoder,
	}, nil
}

func (s Service) AuthCallout(r micro.Request) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	requestClaims, err := s.decodeAuthorizationRequestClaims(r)
	if err != nil {
		log.Printf("[auth.Handle]: %s", err)
		r.Error(StatusBadRequest, err.Error(), nil)
		return
	}

	userNkey := requestClaims.UserNkey
	serverId := requestClaims.Server.ID
	userClaims := jwt.NewUserClaims(requestClaims.UserNkey)

	// decode provided token to give claims from a web
	webClaims, err := s.decoder.Decode(requestClaims.ConnectOptions.Token)
	if err != nil {
		log.Printf("[auth.Handle]: can't decode user token: %s", err)
		r.Error(StatusBadRequest, err.Error(), nil)
		return
	}

	// need to find a issuer and sub
	issuer, _ := webClaims.GetIssuer()
	sub, _ := webClaims.GetSubject()

	uid, err := s.accounts.Linked(ctx, issuer, sub)
	if err != nil {
		log.Printf("[auth.Handle]: %s", err)
		r.Error(StatusBadRequest, err.Error(), nil)
		return
	}
	userClaims.ID = uid.String()
	userClaims.Audience = "PLA" // aka plainsof
	// TODO: which permissions do we need?

	token, err := validateAndSign(userClaims, s.issuerKeyPair)
	log.Printf("[auth.Handle]: ValidateAndSign(): %s, %+v", token, err)
	s.replyAuthorizationResponseClaims(r, userNkey, serverId, token, err)
}

// from nasts-server source code
const AuthRequestXKeyHeader = "Nats-Server-Xkey"

func (s Service) decodeAuthorizationRequestClaims(r micro.Request) (*jwt.AuthorizationRequestClaims, error) {
	var data []byte
	if s.xKeyPair == nil {
		data = r.Data()
	} else {
		xkey := r.Headers().Get(AuthRequestXKeyHeader)
		if xkey == "" {
			return nil, errors.New("missing xkey header, unencrypted auth-callout requests are not supported")
		}
		decrypted, err := s.xKeyPair.Open(r.Data(), xkey)
		if err != nil {
			return nil, fmt.Errorf("curve open: %w", err)
		}
		data = decrypted
	}
	rc, err := jwt.DecodeAuthorizationRequestClaims(string(data))
	if err != nil {
		return nil, err
	}
	return rc, nil
}

func (s Service) replyAuthorizationResponseClaims(req micro.Request, userNKey, serverId, userJWT string, err error) {
	rc := jwt.NewAuthorizationResponseClaims(userNKey)
	rc.Audience = serverId
	rc.Jwt = userJWT
	if err != nil {
		rc.Error = err.Error()
	}

	token, err := rc.Encode(s.issuerKeyPair)
	if err != nil {
		log.Println("error encoding response jwt:", err)
	}

	err = req.Respond([]byte(token))
	log.Printf("[auth.Respond]: Respond: token: %s, err: %+v", token, err)
}

func validateAndSign(claims *jwt.UserClaims, kp nkeys.KeyPair) (string, error) {
	// Validate the claims.
	vr := jwt.CreateValidationResults()
	claims.Validate(vr)
	if len(vr.Errors()) > 0 {
		return "", errors.Join(vr.Errors()...)
	}

	// Sign it with the issuer key since this is non-operator mode.
	return claims.Encode(kp)
}
