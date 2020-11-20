package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/pkg/errors"
	"gopkg.in/h2non/gentleman.v2"
	"gopkg.in/h2non/gentleman.v2/plugin"
	"gopkg.in/h2non/gentleman.v2/plugins/query"
	"gopkg.in/h2non/gentleman.v2/plugins/timeout"

	jwt "github.com/gbrlsnchs/jwt/v2"
)

// ErrRefreshExhausted indicates a refresh token has been used too many times and is no longer valid.
// A new token must be fetched.
var ErrRefreshExhausted = errors.New("refresh token exhausted")

// ErrSessionExpired indicates a login session has reached its maximum allowed time, and a new session
// is required to continue.
var ErrSessionExpired = errors.New("auth session expired")

// Config is the keycloak client http config.
type Config struct {
	AddrTokenProvider string
	AddrAPI           string
	Timeout           time.Duration
}

// TokenInfo represents a full oAuth2 JWT token response with expiration and refresh
type TokenInfo struct {
	TokenType      string
	AccessToken    string
	Expires        time.Time
	RefreshToken   string
	RefreshExpires time.Time
}

// tokenJSON is the struct representing the HTTP response from OAuth2
// providers returning a token in JSON form
type tokenJSON struct {
	TokenType        string `json:"token_type"`
	AccessToken      string `json:"access_token"`
	ExpiresIn        int32  `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int32  `json:"refresh_expires_in"`
}

// toTokenInfo translates the expires information in a tokenJSON to a full token with
// time.Time values. The issued at (iat) value must be when the token was issued
// or expiration values will not calculate correctly
func (t *tokenJSON) toTokenInfo(iat time.Time) TokenInfo {
	token := TokenInfo{
		TokenType:    t.TokenType,
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
	}
	token.Expires = iat.Add(time.Duration(t.ExpiresIn) * time.Second)
	token.RefreshExpires = iat.Add(time.Duration(t.RefreshExpiresIn) * time.Second)
	return token
}

// Client is the keycloak client.
type Client struct {
	tokenProviderURL *url.URL
	apiURL           *url.URL
	httpClient       *gentleman.Client
	tokens           map[string]TokenInfo
}

// HTTPError is returned when an error occured while contacting the keycloak instance.
type HTTPError struct {
	HTTPStatus int
	Message    string
}

func (e HTTPError) Error() string {
	return e.Message
}

// New returns a keycloak client.
func New(config Config) (*Client, error) {
	var uToken *url.URL
	{
		var err error
		uToken, err = url.Parse(config.AddrTokenProvider)
		if err != nil {
			return nil, errors.Wrap(err, "could not parse Token Provider URL")
		}
	}

	var uAPI *url.URL
	{
		var err error
		uAPI, err = url.Parse(config.AddrAPI)
		if err != nil {
			return nil, errors.Wrap(err, "could not parse API URL")
		}
	}

	var httpClient = gentleman.New()
	{
		httpClient = httpClient.URL(uAPI.String())
		httpClient = httpClient.Use(timeout.Request(config.Timeout))
	}

	return &Client{
		tokenProviderURL: uToken,
		apiURL:           uAPI,
		httpClient:       httpClient,
		tokens:           map[string]TokenInfo{},
	}, nil
}

// FetchToken fetches a valid token from keycloak.
func (c *Client) FetchToken(realm string, username string, password string) (TokenInfo, error) {
	var req *gentleman.Request
	{
		var authPath = fmt.Sprintf("/auth/realms/%s/protocol/openid-connect/token", realm)
		req = c.httpClient.Post()
		req = req.SetHeader("Content-Type", "application/x-www-form-urlencoded")
		req = req.Path(authPath)
		req = req.Type("urlencoded")
		req = req.BodyString(fmt.Sprintf("username=%s&password=%s&grant_type=password&client_id=admin-cli", username, password))
	}

	var resp *gentleman.Response
	{
		var err error
		resp, err = req.Do()
		if err != nil {
			return TokenInfo{}, errors.Wrap(err, "could not get token")
		}
	}
	defer resp.Close()

	var tokenResponse tokenJSON
	{
		var err error
		err = resp.JSON(&tokenResponse)
		if err != nil {
			return TokenInfo{}, errors.Wrap(err, "could not unmarshal response")
		}
	}
	// For simplicity, just use time.Now with a 3 second back-date
	// Otherwise this requires parsing headers, the token itself, and requires the
	// server times are 100% synced. This is less overhead and plenty accurate
	tokenInfo := tokenResponse.toTokenInfo(time.Now().Add(time.Duration(-3)))

	return tokenInfo, nil
}

// RefreshToken fetches a valid token from keycloak using the refresh token.
func (c *Client) RefreshToken(realm string, info TokenInfo) (TokenInfo, error) {
	var req *gentleman.Request
	{
		var authPath = fmt.Sprintf("/auth/realms/%s/protocol/openid-connect/token", realm)
		req = c.httpClient.Post()
		req = req.SetHeader("Content-Type", "application/x-www-form-urlencoded")
		req = req.Path(authPath)
		req = req.Type("urlencoded")
		req = req.BodyString(fmt.Sprintf("refresh_token=%s&grant_type=refresh_token&client_id=admin-cli", info.RefreshToken))
	}

	var resp *gentleman.Response
	{
		var err error
		resp, err = req.Do()
		if err != nil {
			return TokenInfo{}, errors.Wrap(err, "could not get token through refresh")
		}
	}
	defer resp.Close()
	if !resp.Ok {
		var respErr map[string]string
		err := resp.JSON(&respErr)
		if err != nil {
			return TokenInfo{}, errors.Wrap(err, "could not unmarshal error response")
		}
		// Map some known errors to defined error objects
		switch respErr["error_description"] {
		case "Maximum allowed refresh token reuse exceeded":
			err = ErrRefreshExhausted
		case "Session not active":
			err = ErrSessionExpired
		default:
			err = errors.New(fmt.Sprintf("fetch error(%d): %s: %s", resp.StatusCode, respErr["error"], respErr["error_description"]))
		}
		return TokenInfo{}, err
	}

	var tokenResponse tokenJSON
	{
		var err error
		err = resp.JSON(&tokenResponse)
		if err != nil {
			return TokenInfo{}, errors.Wrap(err, "could not unmarshal response")
		}
	}
	// For simplicity, just use time.Now with an error threshold
	tokenInfo := tokenResponse.toTokenInfo(time.Now())

	return tokenInfo, nil
}

// GetToken returns a valid token from the cache or from keycloak as needed.
func (c *Client) GetToken(realm string, username string, password string) (string, error) {
	var err error
	key := realm + username
	info, ok := c.tokens[key]
	if !ok || time.Now().After(info.RefreshExpires) {
		// Token was not found, or no longer refreshable, start a new session
		info, err = c.FetchToken(realm, username, password)
		if err != nil {
			delete(c.tokens, key)
			return "", err
		}
		// Cache the token in memory
		c.tokens[key] = info
	} else if time.Now().After(info.Expires) {
		// Token expired, refresh possible, attempt to use refresh
		info, err = c.RefreshToken(realm, info)
		if err != nil {
			// when a session has expired, or a token is exhausted, start a new session
			if err == ErrRefreshExhausted || err == ErrSessionExpired {
				info, err = c.FetchToken(realm, username, password)
				// really, this should not occur, but just in case
				if err != nil {
					return "", err
				}
			} else {
				// Couldn't refresh the session due to an unexpected error
				// clear the cache and restart report the error
				delete(c.tokens, key)
				return "", err
			}
		}
		// Update the cache with the new token info after refreshing
		c.tokens[key] = info
	}
	// The token is available at this point, either from the cache, newly fetched
	// or through a refresh flow. Return it in a way compatible with the former
	// behavior of this method.
	return info.AccessToken, err
}

// verifyToken token verify a token. It returns an error it is malformed, expired,...
func (c *Client) VerifyToken(realmName string, accessToken string) error {
	var oidcProvider *oidc.Provider
	{
		var err error
		var issuer = fmt.Sprintf("%s/auth/realms/%s", c.tokenProviderURL.String(), realmName)
		oidcProvider, err = oidc.NewProvider(context.Background(), issuer)
		if err != nil {
			return errors.Wrap(err, "could not create oidc provider")
		}
	}

	var v = oidcProvider.Verifier(&oidc.Config{SkipClientIDCheck: true})

	var err error
	_, err = v.Verify(context.Background(), accessToken)
	return err
}

// get is a HTTP get method.
func (c *Client) get(accessToken string, data interface{}, plugins ...plugin.Plugin) error {
	var err error
	var req = c.httpClient.Get()
	req = applyPlugins(req, plugins...)
	req, err = setAuthorisationAndHostHeaders(req, accessToken)

	if err != nil {
		return err
	}

	var resp *gentleman.Response
	{
		var err error
		resp, err = req.Do()
		if err != nil {
			return errors.Wrap(err, "could not get response")
		}

		switch {
		case resp.StatusCode == http.StatusUnauthorized:
			return HTTPError{
				HTTPStatus: resp.StatusCode,
				Message:    string(resp.Bytes()),
			}
		case resp.StatusCode >= 400:
			var response map[string]string
			err := json.Unmarshal(resp.Bytes(), &response)
			if message, ok := response["errorMessage"]; ok && err == nil {
				return HTTPError{
					HTTPStatus: resp.StatusCode,
					Message:    message,
				}
			}
			return HTTPError{
				HTTPStatus: resp.StatusCode,
				Message:    string(resp.Bytes()),
			}
		case resp.StatusCode >= 200:
			switch resp.Header.Get("Content-Type") {
			case "application/json":
				return resp.JSON(data)
			case "application/octet-stream":
				data = resp.Bytes()
				return nil
			default:
				return fmt.Errorf("unkown http content-type: %v", resp.Header.Get("Content-Type"))
			}
		default:
			return fmt.Errorf("unknown response status code: %v", resp.StatusCode)
		}
	}
}

func (c *Client) post(accessToken string, data interface{}, plugins ...plugin.Plugin) (string, error) {
	var err error
	var req = c.httpClient.Post()
	req = applyPlugins(req, plugins...)
	req, err = setAuthorisationAndHostHeaders(req, accessToken)

	if err != nil {
		return "", err
	}

	var resp *gentleman.Response
	{
		var err error
		resp, err = req.Do()
		if err != nil {
			return "", errors.Wrap(err, "could not get response")
		}

		switch {
		case resp.StatusCode == http.StatusUnauthorized:
			return "", HTTPError{
				HTTPStatus: resp.StatusCode,
				Message:    string(resp.Bytes()),
			}
		case resp.StatusCode >= 400:
			var response map[string]string
			err := json.Unmarshal(resp.Bytes(), &response)
			if message, ok := response["errorMessage"]; ok && err == nil {
				return "", HTTPError{
					HTTPStatus: resp.StatusCode,
					Message:    message,
				}
			}
			return "", HTTPError{
				HTTPStatus: resp.StatusCode,
				Message:    string(resp.Bytes()),
			}
		case resp.StatusCode >= 200:
			var location = resp.Header.Get("Location")
			switch resp.Header.Get("Content-Type") {
			case "application/json":
				return location, resp.JSON(data)
			case "application/octet-stream":
				data = resp.Bytes()
				return location, nil
			default:
				return location, nil
			}
		default:
			return "", fmt.Errorf("unknown response status code: %v", resp.StatusCode)
		}
	}
}

func (c *Client) delete(accessToken string, plugins ...plugin.Plugin) error {
	var err error
	var req = c.httpClient.Delete()
	req = applyPlugins(req, plugins...)
	req, err = setAuthorisationAndHostHeaders(req, accessToken)

	if err != nil {
		return err
	}

	var resp *gentleman.Response
	{
		var err error
		resp, err = req.Do()
		if err != nil {
			return errors.Wrap(err, "could not get response")
		}

		switch {
		case resp.StatusCode == http.StatusUnauthorized:
			return HTTPError{
				HTTPStatus: resp.StatusCode,
				Message:    string(resp.Bytes()),
			}
		case resp.StatusCode >= 400:
			var response map[string]string
			err := json.Unmarshal(resp.Bytes(), &response)
			if message, ok := response["errorMessage"]; ok && err == nil {
				return HTTPError{
					HTTPStatus: resp.StatusCode,
					Message:    message,
				}
			}
			return HTTPError{
				HTTPStatus: resp.StatusCode,
				Message:    string(resp.Bytes()),
			}
		case resp.StatusCode >= 200:
			return nil
		default:
			return HTTPError{
				HTTPStatus: resp.StatusCode,
				Message:    string(resp.Bytes()),
			}
		}
	}
}

// createVanillaRequest isolates duplicate code in creating http requests.
func createVanillaRequest(method string, path string, params interface{}) (*http.Request, error) {
	var buf bytes.Buffer
	var request *http.Request
	err := json.NewEncoder(&buf).Encode(&params)
	if err != nil {
		return request, err
	}
	request, err = http.NewRequest(method, path, &buf)
	if err != nil {
		return request, HTTPError{
			HTTPStatus: 0,
			Message:    fmt.Sprintf("createVanillaRequest: error %s: creating request for %s %s %v", err, method, path, params),
		}
	}
	return request, nil
}

// makeJSONCall sends a request, auto decoding the response to the result interface if sent.
func makeJSONCall(accessToken string, request *http.Request, result interface{}) error {
	client := &http.Client{}

	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		requestURL := request.URL.String()
		return HTTPError{
			HTTPStatus: response.StatusCode,
			Message:    fmt.Sprintf("%s: server http error %d", requestURL, response.StatusCode),
		}
	}
	defer response.Body.Close()
	if !(response.StatusCode >= 200 && response.StatusCode <= 299) {
		requestURL := request.URL.String()
		return HTTPError{
			HTTPStatus: response.StatusCode,
			Message:    fmt.Sprintf("%s: server http error %d", requestURL, response.StatusCode),
		}
	}
	// If no result is expected, don't attempt to decode a potentially
	// empty response stream and avoid incurring EOF errors
	if result == nil {
		return nil
	}

	// var bodyBytes []byte
	// if response.Body != nil {
	// 	bodyBytes, err = ioutil.ReadAll(response.Body)
	// 	if err != nil {
	// 		fmt.Printf("Error reading request body %s", err)
	// 	}
	// }

	// fmt.Printf("Raw Response %s", string(bodyBytes))

	// // Repopulate body with the data read
	// response.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		requestURL := request.URL.String()
		return HTTPError{
			HTTPStatus: response.StatusCode,
			Message:    fmt.Sprintf("%s: server http error %d", requestURL, response.StatusCode),
		}
	}
	return nil
}

// makePlainTextCall sends a request, return the plain text response and error (if any).
func makePlainTextCall(accessToken string, request *http.Request) (string, error) {
	var body string
	client := &http.Client{}

	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("Content-Type", "text/plain")

	response, err := client.Do(request)
	if err != nil {
		requestURL := request.URL.String()
		return body, HTTPError{
			HTTPStatus: response.StatusCode,
			Message:    fmt.Sprintf("%s: server http error %d", requestURL, response.StatusCode),
		}
	}
	defer response.Body.Close()
	if !(response.StatusCode >= 200 && response.StatusCode <= 299) {
		requestURL := request.URL.String()
		return body, HTTPError{
			HTTPStatus: response.StatusCode,
			Message:    fmt.Sprintf("%s: server http error %d", requestURL, response.StatusCode),
		}
	}
	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return body, err
	}

	body = string(bodyBytes)
	return body, nil
}

func (c *Client) put(accessToken string, plugins ...plugin.Plugin) error {
	var err error
	var req = c.httpClient.Put()
	req = applyPlugins(req, plugins...)
	req, err = setAuthorisationAndHostHeaders(req, accessToken)

	if err != nil {
		return err
	}

	var resp *gentleman.Response
	{
		var err error
		resp, err = req.Do()
		if err != nil {
			return errors.Wrap(err, "could not get response")
		}

		switch {
		case resp.StatusCode == http.StatusUnauthorized:
			return HTTPError{
				HTTPStatus: resp.StatusCode,
				Message:    string(resp.Bytes()),
			}
		case resp.StatusCode >= 400:
			var response map[string]string
			err := json.Unmarshal(resp.Bytes(), &response)
			if message, ok := response["errorMessage"]; ok && err == nil {
				return HTTPError{
					HTTPStatus: resp.StatusCode,
					Message:    message,
				}
			}
			return HTTPError{
				HTTPStatus: resp.StatusCode,
				Message:    string(resp.Bytes()),
			}
		case resp.StatusCode >= 200:
			return nil
		default:
			return HTTPError{
				HTTPStatus: resp.StatusCode,
				Message:    string(resp.Bytes()),
			}
		}
	}
}

func setAuthorisationAndHostHeaders(req *gentleman.Request, accessToken string) (*gentleman.Request, error) {
	host, err := extractHostFromToken(accessToken)

	if err != nil {
		return req, err
	}

	var r = req.SetHeader("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	r = r.SetHeader("X-Forwarded-Proto", "https")

	r.Context.Request.Host = host

	return r, nil
}

// applyPlugins apply all the plugins to the request req.
func applyPlugins(req *gentleman.Request, plugins ...plugin.Plugin) *gentleman.Request {
	var r = req
	for _, p := range plugins {
		r = r.Use(p)
	}
	return r
}

func extractHostFromToken(token string) (string, error) {
	issuer, err := extractIssuerFromToken(token)

	if err != nil {
		return "", err
	}

	var u *url.URL
	{
		var err error
		u, err = url.Parse(issuer)
		if err != nil {
			return "", errors.Wrap(err, "could not parse Token issuer URL")
		}
	}

	return u.Host, nil
}

func extractIssuerFromToken(token string) (string, error) {
	payload, _, err := jwt.Parse(token)

	if err != nil {
		return "", errors.Wrap(err, "could not parse Token")
	}

	var jot Token

	if err = jwt.Unmarshal(payload, &jot); err != nil {
		return "", errors.Wrap(err, "could not unmarshall token")
	}

	return jot.Issuer, nil
}

// createQueryPlugins create query parameters with the key values paramKV.
func createQueryPlugins(paramKV ...string) []plugin.Plugin {
	var plugins = []plugin.Plugin{}
	for i := 0; i < len(paramKV); i += 2 {
		var k = paramKV[i]
		var v = paramKV[i+1]
		plugins = append(plugins, query.Add(k, v))
	}
	return plugins
}

func str(s string) *string {
	return &s
}

// Token is JWT token.
// We need to define our own structure as the library define aud as a string but it can also be a string array.
// To fix this issue, we remove aud as we do not use it here.
type Token struct {
	hdr            *header
	Issuer         string `json:"iss,omitempty"`
	Subject        string `json:"sub,omitempty"`
	ExpirationTime int64  `json:"exp,omitempty"`
	NotBefore      int64  `json:"nbf,omitempty"`
	IssuedAt       int64  `json:"iat,omitempty"`
	ID             string `json:"jti,omitempty"`
	Username       string `json:"preferred_username,omitempty"`
}

type header struct {
	Algorithm   string `json:"alg,omitempty"`
	KeyID       string `json:"kid,omitempty"`
	Type        string `json:"typ,omitempty"`
	ContentType string `json:"cty,omitempty"`
}
