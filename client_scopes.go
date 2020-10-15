package keycloak

import (
	"gopkg.in/h2non/gentleman.v2/plugins/url"
)

const (
	defaultClientScopesPath       = "/auth/admin/realms/:realm/clients/:client/default-client-scopes"
	defaultClientScopePath        = "/auth/admin/realms/:realm/clients/:client/default-client-scopes/:scope"
	optionalClientScopesPath      = "/auth/admin/realms/:realm/clients/:client/optional-client-scopes"
	optionalClientScopePath       = "/auth/admin/realms/:realm/clients/:client/optional-client-scopes/:scope"
	realmDefaultClientScopesPath  = "/auth/admin/realms/:realm/default-default-client-scopes"
	realmDefaultClientScopePath   = "/auth/admin/realms/:realm/default-default-client-scopes/:scope"
	realmOptionalClientScopesPath = "/auth/admin/realms/:realm/default-optional-client-scopes"
	realmOptionalClientScopePath  = "/auth/admin/realms/:realm/default-optional-client-scopes/:scope"
)

// GetRealmDefaultClientScopes gets realm configuration for scopes which are added as client default scopes when a new client is created
// GET /auth/admin/realms/demorealm/default-default-client-scopes HTTP/1.1
// [
//     {
//         "id":"3f4f9602-f843-48a6-9d24-0f9563eed5b0",
//         "name":"profile"
//     },
//     {
//         "id":"7efa02d9-0a1e-496d-abf7-d9edb80e47b3",
//         "name":"email"
//     },
//     {
//         "id":"2c683450-ae2d-48ef-ace3-bc9101b2c4d1",
//         "name":"web-origins"
//     }
// ]
func (c *Client) GetRealmDefaultClientScopes(accessToken string, realmName string) ([]ClientScopeRepresentation, error) {
	var resp = []ClientScopeRepresentation{}
	var err = c.get(accessToken, &resp, url.Path(realmDefaultClientScopesPath), url.Param("realm", realmName))
	return resp, err
}

// AddRealmDefaultClientScope changes the default client scopes for a realm to add the scope represented by scopeId
// PUT /auth/admin/realms/demorealm/default-default-client-scopes/2c683450-ae2d-48ef-ace3-bc9101b2c4d1 HTTP/1.1
// 204
func (c *Client) AddRealmDefaultClientScope(accessToken string, realmName, scope string) error {
	err := c.put(accessToken, nil, url.Path(realmDefaultClientScopePath), url.Param("realm", realmName), url.Param("scope", scope))
	return err
}

// RemoveRealmDefaultClientScope changes the default client scopes for a realm to add the scope represented by scopeId
// DELETE /auth/admin/realms/demorealm/default-default-client-scopes/2c683450-ae2d-48ef-ace3-bc9101b2c4d1 HTTP/1.1
// 204
func (c *Client) RemoveRealmDefaultClientScope(accessToken string, realmName, scope string) error {
	err := c.delete(accessToken, url.Path(realmDefaultClientScopePath), url.Param("realm", realmName), url.Param("scope", scope))
	return err
}

// GetRealmOptionalClientScopes gets realm configuration for scopes which are added as client optional scopes when a new client is created
// GET /auth/admin/realms/demorealm/default-optional-client-scopes HTTP/1.1
// [
//     {
//         "id":"3f4f9602-f843-48a6-9d24-0f9563eed5b0",
//         "name":"profile"
//     },
//     {
//         "id":"7efa02d9-0a1e-496d-abf7-d9edb80e47b3",
//         "name":"email"
//     },
//     {
//         "id":"2c683450-ae2d-48ef-ace3-bc9101b2c4d1",
//         "name":"web-origins"
//     }
// ]
func (c *Client) GetRealmOptionalClientScopes(accessToken string, realmName string) ([]ClientScopeRepresentation, error) {
	var resp = []ClientScopeRepresentation{}
	var err = c.get(accessToken, &resp, url.Path(realmOptionalClientScopesPath), url.Param("realm", realmName))
	return resp, err
}

// AddRealmOptionalClientScope changes the optional client scopes for a realm to add the scope represented by scopeId
// PUT /auth/admin/realms/demorealm/default-optional-client-scopes/2c683450-ae2d-48ef-ace3-bc9101b2c4d1 HTTP/1.1
// 204
func (c *Client) AddRealmOptionalClientScope(accessToken string, realmName, scope string) error {
	err := c.put(accessToken, nil, url.Path(realmOptionalClientScopePath), url.Param("realm", realmName), url.Param("scope", scope))
	return err
}

// RemoveRealmOptionalClientScope changes the optional client scopes for a realm to add the scope represented by scopeId
// DELETE /auth/admin/realms/demorealm/default-optional-client-scopes/2c683450-ae2d-48ef-ace3-bc9101b2c4d1 HTTP/1.1
// 204
func (c *Client) RemoveRealmOptionalClientScope(accessToken string, realmName, scope string) error {
	err := c.delete(accessToken, url.Path(realmOptionalClientScopePath), url.Param("realm", realmName), url.Param("scope", scope))
	return err
}

// GetDefaultClientScopes gets realm configuration for scopes which are added as client default scopes when a new client is created
// GET /auth/admin/realms/demorealm/clients/0d55d933-09f4-427d-a385-13f5ceb1656e/default-client-scopes HTTP/1.1
// [
//     {
//         "id":"3f4f9602-f843-48a6-9d24-0f9563eed5b0",
//         "name":"profile"
//     },
//     {
//         "id":"7efa02d9-0a1e-496d-abf7-d9edb80e47b3",
//         "name":"email"
//     },
//     {
//         "id":"2c683450-ae2d-48ef-ace3-bc9101b2c4d1",
//         "name":"web-origins"
//     }
// ]
func (c *Client) GetDefaultClientScopes(accessToken string, realmName, client string) ([]ClientScopeRepresentation, error) {
	var resp = []ClientScopeRepresentation{}
	var err = c.get(accessToken, &resp, url.Path(defaultClientScopesPath), url.Param("realm", realmName), url.Param("client", client))
	return resp, err
}

// AddDefaultClientScope changes the default client scopes for a realm to add the scope represented by scopeId
// PUT /auth/admin/realms/demorealm/clients/0d55d933-09f4-427d-a385-13f5ceb1656e/default-client-scopes/7efa02d9-0a1e-496d-abf7-d9edb80e47b3 HTTP/1.1
// 204
func (c *Client) AddDefaultClientScope(accessToken string, realmName, client, scope string) error {
	err := c.put(accessToken, url.Path(defaultClientScopePath), url.Param("realm", realmName), url.Param("client", client), url.Param("scope", scope))
	return err
}

// RemoveDefaultClientScope changes the default client scopes for a realm to add the scope represented by scopeId
// DELETE /auth/admin/realms/demorealm/clients/0d55d933-09f4-427d-a385-13f5ceb1656e/default-client-scopes/7efa02d9-0a1e-496d-abf7-d9edb80e47b3 HTTP/1.1
// 204
func (c *Client) RemoveDefaultClientScope(accessToken string, realmName, client, scope string) error {
	err := c.delete(accessToken, url.Path(defaultClientScopePath), url.Param("realm", realmName), url.Param("client", client), url.Param("scope", scope))
	return err
}

// GetOptionalClientScopes gets realm configuration for scopes which are added as client optional scopes when a new client is created
// GET /auth/admin/realms/demorealm/clients/0d55d933-09f4-427d-a385-13f5ceb1656e/optional-client-scopes HTTP/1.1
// [
//     {
//         "id":"3f4f9602-f843-48a6-9d24-0f9563eed5b0",
//         "name":"profile"
//     },
//     {
//         "id":"7efa02d9-0a1e-496d-abf7-d9edb80e47b3",
//         "name":"email"
//     },
//     {
//         "id":"2c683450-ae2d-48ef-ace3-bc9101b2c4d1",
//         "name":"web-origins"
//     }
// ]
func (c *Client) GetOptionalClientScopes(accessToken string, realmName, client string) ([]ClientScopeRepresentation, error) {
	var resp = []ClientScopeRepresentation{}
	var err = c.get(accessToken, &resp, url.Path(optionalClientScopesPath), url.Param("realm", realmName), url.Param("client", client))
	return resp, err
}

// AddOptionalClientScope changes the optional client scopes for a realm to add the scope represented by scopeId
// PUT /auth/admin/realms/demorealm/clients/0d55d933-09f4-427d-a385-13f5ceb1656e/optional-client-scopes/7efa02d9-0a1e-496d-abf7-d9edb80e47b3 HTTP/1.1
// 204
func (c *Client) AddOptionalClientScope(accessToken string, realmName, client, scope string) error {
	err := c.put(accessToken, url.Path(optionalClientScopePath), url.Param("realm", realmName), url.Param("client", client), url.Param("scope", scope))
	return err
}

// RemoveOptionalClientScope changes the optional client scopes for a realm to add the scope represented by scopeId
// DELETE /auth/admin/realms/demorealm/clients/0d55d933-09f4-427d-a385-13f5ceb1656e/optional-client-scopes/7efa02d9-0a1e-496d-abf7-d9edb80e47b3 HTTP/1.1
// 204
func (c *Client) RemoveOptionalClientScope(accessToken string, realmName, client, scope string) error {
	err := c.delete(accessToken, url.Path(optionalClientScopePath), url.Param("realm", realmName), url.Param("client", client), url.Param("scope", scope))
	return err
}
