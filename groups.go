package keycloak

import (
	"gopkg.in/h2non/gentleman.v2/plugins/body"
	"gopkg.in/h2non/gentleman.v2/plugins/url"
)

const (
	groupsPath    = "/auth/admin/realms/:realm/groups"
	groupByIDPath = "/auth/admin/realms/:realm/groups/:id"
)

// CreateClientRole creates a new role for the realm or client
func (c *Client) CreateGroup(accessToken string, realmName string, group GroupRepresentation) (string, error) {
	return c.post(accessToken, nil, url.Path(groupsPath), url.Param("realm", realmName), body.JSON(group))
}

// DeleteRole deletes a role
func (c *Client) DeleteGroup(accessToken string, realmName string, groupID string) error {
	return c.delete(accessToken, url.Path(groupByIDPath), url.Param("realm", realmName), url.Param("id", groupID))
}

// GetGroups gets all groups for the realm
func (c *Client) GetGroups(accessToken string, realmName string) ([]GroupRepresentation, error) {
	var resp = []GroupRepresentation{}
	var err = c.get(accessToken, &resp, url.Path(groupsPath), url.Param("realm", realmName))
	return resp, err
}

// GetGroup gets a specific group’s representation
func (c *Client) GetGroup(accessToken string, realmName string, groupID string) (GroupRepresentation, error) {
	var resp = GroupRepresentation{}
	var err = c.get(accessToken, &resp, url.Path(groupByIDPath), url.Param("realm", realmName), url.Param("id", groupID))
	return resp, err
}
