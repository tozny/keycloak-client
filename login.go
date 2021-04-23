package keycloak

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/gorilla/schema"
	"github.com/pkg/errors"
	"gopkg.in/h2non/gentleman.v2"
)

const (
	initiateLoginPath = "/auth/realms/%s/protocol/openid-connect/auth"
)

var (
	encoder = schema.NewEncoder()
)

// InitiateLogin begins the login flow
func (c *Client) InitiateLogin(realmName string, loginURLEncoded InitiatePKCELogin) (*http.Response, error) {
	var req *gentleman.Request
	{
		var authPath = fmt.Sprintf(initiateLoginPath, realmName)
		req = c.httpClient.Post()
		req = req.SetHeader("Content-Type", "application/x-www-form-urlencoded")
		req = req.Path(authPath)
		req = req.Type("urlencoded")
		data := url.Values{}
		encoder.Encode(loginURLEncoded, data)
		req = req.BodyString(data.Encode())
	}
	var resp *gentleman.Response
	{
		var err error
		resp, err = req.Do()
		if err != nil {
			return nil, errors.Wrap(err, "Could not Initiate Login")
		}
	}
	return resp.RawResponse, nil
}
