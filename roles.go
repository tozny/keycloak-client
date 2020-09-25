package keycloak

import (
	"gopkg.in/h2non/gentleman.v2/plugins/body"
	"gopkg.in/h2non/gentleman.v2/plugins/url"
)

const (
	rolePath       = "/auth/admin/realms/:realm/roles"
	roleByIDPath   = "/auth/admin/realms/:realm/roles-by-id/:id"
	clientRolesPath = "/auth/admin/realms/:realm/clients/:id/roles"
	clientRolePath = "/auth/admin/realms/:realm/clients/:id/roles/:role_id"
)

// GetClientRoles gets all roles for the realm or client
func (c *Client) GetClientRoles(accessToken string, realmName string, clientID string) ([]RoleRepresentation, error) {
	var resp = []RoleRepresentation{}
	var err = c.get(accessToken, &resp, url.Path(clientRolesPath), url.Param("realm", realmName), url.Param("id", clientID))
	return resp, err
}

// CreateClientRole creates a new role for the realm or client
func (c *Client) CreateClientRole(accessToken string, realmName string, clientID string, role RoleRepresentation) (string, error) {
	return c.post(accessToken, nil, url.Path(clientRolesPath), url.Param("realm", realmName), url.Param("id", clientID), body.JSON(role))
}

// DeleteRole deletes a role
func (c *Client) DeleteRole(accessToken string, realmName string, clientID string, roleID string) error {
	return c.delete(accessToken, url.Path(clientRolePath), url.Param("realm", realmName), url.Param("id", clientID), url.Param("role_id", roleID))
}

// GetRoles gets all roles for the realm or client
func (c *Client) GetRoles(accessToken string, realmName string) ([]RoleRepresentation, error) {
	var resp = []RoleRepresentation{}
	var err = c.get(accessToken, &resp, url.Path(rolePath), url.Param("realm", realmName))
	return resp, err
}

// GetRole gets a specific role’s representation
func (c *Client) GetRole(accessToken string, realmName string, roleID string) (RoleRepresentation, error) {
	var resp = RoleRepresentation{}
	var err = c.get(accessToken, &resp, url.Path(roleByIDPath), url.Param("realm", realmName), url.Param("id", roleID))
	return resp, err
}

// GetClientRole gets a specific client role’s representation
func (c *Client) GetClientRole(accessToken string, realmName string, clientID string, roleID string) (RoleRepresentation, error) {
	var resp = RoleRepresentation{}
	var err = c.get(accessToken, &resp, url.Path(clientRolePath), url.Param("realm", realmName), url.Param("id", clientID), url.Param("role_id", roleID))
	return resp, err
}
