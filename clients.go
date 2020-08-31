package keycloak

import (
	"fmt"

	"gopkg.in/h2non/gentleman.v2/plugins/body"
	"gopkg.in/h2non/gentleman.v2/plugins/url"
)

const (
	clientsPath  = "/auth/admin/realms/:realm/clients"
	clientIDPath = clientsPath + "/:id"
	clientSecret = clientIDPath + "/client-secret"
)

// GetClients returns a list of clients belonging to the realm.
// Parameters: clientId (filter by clientId),
// viewableOnly (filter clients that cannot be viewed in full by admin, default="false")
func (c *Client) GetClients(accessToken string, realmName string, paramKV ...string) ([]ClientRepresentation, error) {
	if len(paramKV)%2 != 0 {
		return nil, fmt.Errorf("the number of key/val parameters should be even")
	}

	var resp = []ClientRepresentation{}
	var plugins = append(createQueryPlugins(paramKV...), url.Path(clientsPath), url.Param("realm", realmName))
	var err = c.get(accessToken, &resp, plugins...)
	return resp, err
}

// GetClient get the representation of the client. idClient is the id of client (not client-id).
func (c *Client) GetClient(accessToken string, realmName, idClient string) (ClientRepresentation, error) {
	var resp = ClientRepresentation{}
	var err = c.get(accessToken, &resp, url.Path(clientIDPath), url.Param("realm", realmName), url.Param("id", idClient))
	return resp, err
}

// CreateClient creates a client
func (c *Client) CreateClient(accessToken string, realmName string, client ClientCreateRequest) (string, error) {
	return c.post(accessToken, nil, url.Path(clientsPath), url.Param("realm", realmName), body.JSON(client))
}

// UpdateClient updates the client.
func (c *Client) UpdateClient(accessToken string, realmName, clientID string, client ClientRepresentation) error {
	return c.put(accessToken, url.Path(clientIDPath), url.Param("realm", realmName), url.Param("id", clientID), body.JSON(client))
}

// GetSecret get the client secret. idClient is the id of client (not client-id).
func (c *Client) GetSecret(accessToken string, realmName, idClient string) (CredentialRepresentation, error) {
	var resp = CredentialRepresentation{}
	var err = c.get(accessToken, &resp, url.Path(clientSecret), url.Param("realm", realmName), url.Param("id", idClient))
	return resp, err
}

// DeleteClient deletes specified client from the realm. id is the id of client (not client-id).
func (c *Client) DeleteClient(accessToken string, realmName, id string) error {
	return c.delete(accessToken, url.Path(clientIDPath), url.Param("realm", realmName), url.Param("id", id))
}
