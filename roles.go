package keycloak

import (
	"gopkg.in/h2non/gentleman.v2/plugins/body"
	"gopkg.in/h2non/gentleman.v2/plugins/url"
)

const (
	rolePath        = "/auth/admin/realms/:realm/roles"
	roleByNamePath  = "/auth/admin/realms/:realm/roles/:name"
	roleByIDPath    = "/auth/admin/realms/:realm/roles-by-id/:id"
	clientRolesPath = "/auth/admin/realms/:realm/clients/:id/roles"
	clientRolePath  = "/auth/admin/realms/:realm/clients/:id/roles/:role_id"
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

// GetClientRole gets a specific client role’s representation
func (c *Client) GetClientRole(accessToken string, realmName string, clientID string, roleID string) (RoleRepresentation, error) {
	var resp = RoleRepresentation{}
	var err = c.get(accessToken, &resp, url.Path(clientRolePath), url.Param("realm", realmName), url.Param("id", clientID), url.Param("role_id", roleID))
	return resp, err
}

// GetRealmRoles gets all roles for the realm
// GET /auth/admin/realms/demorealm/roles HTTP/1.1
// [{
//     "id": "f19e86ad-ddf2-4397-9a36-63bf02119fe8",
//     "name": "offline_access",
//     "description": "${role_offline-access}",
//     "composite": false,
//     "clientRole": false,
//     "containerId": "b0b76f0e-3405-4d43-97da-4556d4cff122"
// }, {
//     "id": "1776d0d5-5ed6-49fa-83fc-f589b9c43eed",
//     "name": "uma_authorization",
//     "description": "${role_uma_authorization}",
//     "composite": false,
//     "clientRole": false,
//     "containerId": "b0b76f0e-3405-4d43-97da-4556d4cff122"
// }]
func (c *Client) GetRealmRoles(accessToken string, realmName string) ([]RoleRepresentation, error) {
	var resp = []RoleRepresentation{}
	var err = c.get(accessToken, &resp, url.Path(rolePath), url.Param("realm", realmName))
	return resp, err
}

// GetRealmRole gets a specific realm role’s representation
// GET /auth/admin/realms/demorealm/roles/Admin HTTP/1.1
// {
//     "id": "c4d3c739-ad50-421e-a9af-63b04ae4105d",
//     "name": "Admin",
//     "description": "Allow all.",
//     "composite": false,
//     "clientRole": false,
//     "containerId": "b0b76f0e-3405-4d43-97da-4556d4cff122",
//     "attributes": {}
// }
func (c *Client) GetRealmRoleByName(accessToken string, realmName string, roleName string) (RoleRepresentation, error) {
	var resp = RoleRepresentation{}
	var err = c.get(accessToken, &resp, url.Path(roleByNamePath), url.Param("realm", realmName), url.Param("name", roleName))
	return resp, err
}

// GetRealmRole gets a specific realm role’s representation
// GET /auth/admin/realms/demorealm/roles-by-id/f19e86ad-ddf2-4397-9a36-63bf02119fe8
// {
//     "id": "f19e86ad-ddf2-4397-9a36-63bf02119fe8",
//     "name": "offline_access",
//     "description": "${role_offline-access}",
//     "composite": false,
//     "clientRole": false,
//     "containerId": "b0b76f0e-3405-4d43-97da-4556d4cff122",
//     "attributes": {}
// }
func (c *Client) GetRealmRoleByID(accessToken string, realmName string, roleId string) (RoleRepresentation, error) {
	var resp = RoleRepresentation{}
	var err = c.get(accessToken, &resp, url.Path(roleByIDPath), url.Param("realm", realmName), url.Param("id", roleId))
	return resp, err
}

// CreateRealmRole creates a new role for the specified realm
// POST /auth/admin/realms/demorealm/roles HTTP/1.1
// {"name":"Admin Role","description":"Allow all."}
// 201
// Header: Location: http://localhost:8000/auth/admin/realms/demorealm/roles/Admin%sRole
func (c *Client) CreateRealmRole(accessToken string, realmName string, role RoleRepresentation) (string, error) {
	return c.post(accessToken, nil, url.Path(rolePath), url.Param("realm", realmName), body.JSON(role))
}

// DeleteRealmRole deletes the specified role from the specified realm
// DELETE /auth/admin/realms/demorealm/roles-by-id/c4d3c739-ad50-421e-a9af-63b04ae4105d HTTP/1.1
func (c *Client) DeleteRealmRole(accessToken string, realmName string, roleId string) error {
	var err = c.delete(accessToken, url.Path(roleByIDPath), url.Param("realm", realmName), url.Param("id", roleId))
	return err
}
