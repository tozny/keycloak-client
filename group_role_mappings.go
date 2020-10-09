package keycloak

import (
	"gopkg.in/h2non/gentleman.v2/plugins/body"
	"gopkg.in/h2non/gentleman.v2/plugins/url"
)

const (
	groupsRealmRoleMappingPath      = "/auth/admin/realms/:realm/groups/:id/role-mappings/realm"
	groupsRoleMappingByClientIdPath = "/auth/admin/realms/:realm/groups/:group_id/role-mappings/clients/:id"
)

// GetGroupRealmRoleMappings get the realm level roles for the group or error (if any).
// > GET http://localhost:8000/auth/admin/realms/demo/groups/80206962-5dcb-4252-8cbb-2e828c1d010b/role-mappings/realm
// ```json
// [
//   {
//     "id": "f815fc8a-5eb6-46c1-a454-5fbc8e1c6492",
//     "name": "offline_access",
//     "description": "${role_offline-access}",
//     "composite": false,
//     "clientRole": false,
//     "containerId": "4f0f8206-0ec4-4fd6-99eb-4e8c4b986c43"
//   }
// ]
// ```
func (c *Client) GetGroupRealmRoleMappings(accessToken, realmName, groupId string) ([]RoleRepresentation, error) {
	var resp = []RoleRepresentation{}
	var err = c.get(accessToken, &resp, url.Path(groupsRealmRoleMappingPath), url.Param("realm", realmName), url.Param("id", groupId))
	return resp, err
}

// AddGroupRealmRoleMappings adds realm role mapping(s) for the group, returning error (if any).
// > POST http://localhost:8000/auth/admin/realms/demo/groups/80206962-5dcb-4252-8cbb-2e828c1d010b/role-mappings/realm
// ```json
// [
//   {
//     "id": "f815fc8a-5eb6-46c1-a454-5fbc8e1c6492",
//     "name": "offline_access",
//     "description": "${role_offline-access}",
//     "composite": false,
//     "clientRole": false,
//     "containerId": "4f0f8206-0ec4-4fd6-99eb-4e8c4b986c43"
//   }
// ]
// ```
func (c *Client) AddGroupRealmRoleMappings(accessToken, realmName, groupId string, roleMappings []RoleRepresentation) error {
	_, err := c.post(accessToken, nil, url.Path(groupsRealmRoleMappingPath), url.Param("realm", realmName), url.Param("id", groupId), body.JSON(roleMappings))
	return err
}

// RemoveGroupRealmRoleMappings removes realm role mapping(s) from the group
// > DELETE http://localhost:8000/auth/admin/realms/demo/groups/80206962-5dcb-4252-8cbb-2e828c1d010b/role-mappings/realm
// ```json
// [
//   {
//     "id": "f815fc8a-5eb6-46c1-a454-5fbc8e1c6492",
//     "name": "offline_access",
//     "description": "${role_offline-access}",
//     "composite": false,
//     "clientRole": false,
//     "containerId": "4f0f8206-0ec4-4fd6-99eb-4e8c4b986c43"
//   }
// ]
// ```
func (c *Client) RemoveGroupRealmRoleMappings(accessToken, realmName, groupId string, roleMappings []RoleRepresentation) error {
	err := c.delete(accessToken, nil, url.Path(groupsRealmRoleMappingPath), url.Param("realm", realmName), url.Param("id", groupId), body.JSON(roleMappings))
	return err
}

// GetGroupClientRoleMappings returns the assigned client roles for a group and error (if any).
// >	GET http://localhost:8000/auth/admin/realms/demo/groups/80206962-5dcb-4252-8cbb-2e828c1d010b/role-mappings/clients/a3bdb226-f718-4c69-9f59-76df1dda1362
// ```json
// [
//   {
//     "id": "945ae18b-5cd5-48c5-9fa8-e5b43555d71f",
//     "name": "Admin",
//     "description": "Allow all.",
//     "composite": false,
//     "clientRole": true,
//     "containerId": "a3bdb226-f718-4c69-9f59-76df1dda1362"
//   }
// ]
func (c *Client) GetGroupClientRoleMappings(accessToken, realmName, groupId, clientId string) ([]RoleRepresentation, error) {
	var resp = []RoleRepresentation{}
	var err = c.get(accessToken, &resp, url.Path(groupsRoleMappingByClientIdPath), url.Param("realm", realmName), url.Param("group_id", groupId), url.Param("id", clientId))
	return resp, err
}

// AddGroupClientRoleMappings adds client role mappings for a group, returning error (if any)
// >	POST http://localhost:8000/auth/admin/realms/demo/groups/80206962-5dcb-4252-8cbb-2e828c1d010b/role-mappings/clients/a3bdb226-f718-4c69-9f59-76df1dda1362
// ```json
// [
//   {
//     "id": "945ae18b-5cd5-48c5-9fa8-e5b43555d71f",
//     "name": "Admin",
//     "description": "Allow all.",
//     "composite": false,
//     "clientRole": true,
//     "containerId": "a3bdb226-f718-4c69-9f59-76df1dda1362"
//   }
// ]
func (c *Client) AddGroupClientRoleMappings(accessToken, realmName, groupId, clientId string, roleMappings []RoleRepresentation) error {
	_, err := c.post(accessToken, nil, url.Path(groupsRoleMappingByClientIdPath), url.Param("realm", realmName), url.Param("group_id", groupId), url.Param("id", clientId), body.JSON(roleMappings))
	return err
}

// RemoveGroupClientRoleMappings removes client role mapping(s) from a group, returning error (if any)
// >	DELETE http://localhost:8000/auth/admin/realms/demo/groups/80206962-5dcb-4252-8cbb-2e828c1d010b/role-mappings/clients/a3bdb226-f718-4c69-9f59-76df1dda1362
// ```json
// [
//   {
//     "id": "945ae18b-5cd5-48c5-9fa8-e5b43555d71f",
//     "name": "Admin",
//     "description": "Allow all.",
//     "composite": false,
//     "clientRole": true,
//     "containerId": "a3bdb226-f718-4c69-9f59-76df1dda1362"
//   }
// ]
func (c *Client) RemoveGroupClientRoleMappings(accessToken, realmName, groupId, clientId string, roleMappings []RoleRepresentation) error {
	path := c.apiURL.String() + "/auth/admin/realms/" + realmName + "/groups/" + groupId + "/role-mappings/clients/" + clientId
	request, err := createVanillaRequest("DELETE", path, roleMappings)
	if err != nil {
		return err
	}
	return makeVanillaCall(accessToken, request, nil)
}
