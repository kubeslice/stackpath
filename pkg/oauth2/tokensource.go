package oauth2

import (
	"context"
	"fmt"
	"net/http"
	"time"

	user "github.com/wmarchesi123/stackpath-go/pkg/accounts_and_users"
	"golang.org/x/oauth2"
)

// TokenSource is an oauth2 token source for stackpath
type TokenSource struct {
	req    user.IdentityGetAccessTokenRequest
	client *http.Client
}

// Option is used to pass options to the client during creation
type Option func(*TokenSource)

// HTTPClientOption returns an option telling the Client to use the given http.Client
func HTTPClientOption(client *http.Client) Option {
	return func(sps *TokenSource) {
		sps.client = client
	}
}

// NewTokenSource returns a new token source for stackpath
func NewTokenSource(clientid string, clientsecret string, options ...Option) oauth2.TokenSource {
	creds := "client_credentials"
	src := &TokenSource{
		req: user.IdentityGetAccessTokenRequest{
			ClientId:     &clientid,
			ClientSecret: &clientsecret,
			GrantType:    &creds,
		},
	}
	for _, opt := range options {
		opt(src)
	}
	return oauth2.ReuseTokenSource(nil, src)
}

// Token returns a token
func (sps *TokenSource) Token() (*oauth2.Token, error) {

	if *sps.req.ClientId == "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" && *sps.req.ClientSecret == "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" {
		return nil, nil
	}

	usercfg := user.NewConfiguration()
	usercfg.HTTPClient = sps.client
	userclient := user.NewAPIClient(usercfg)
	idresp, _, err := userclient.AuthenticationApi.GetAccessToken(context.Background()).IdentityGetAccessTokenRequest(sps.req).Execute()
	if err != nil {
		return nil, fmt.Errorf("Error obtaining oauth2 token: %v", err)
	}
	return &oauth2.Token{
		AccessToken: *idresp.AccessToken,
		TokenType:   *idresp.TokenType,
		Expiry:      time.Now().Add(time.Second * time.Duration(*idresp.ExpiresIn-30)),
	}, nil
}
