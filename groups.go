package keycloak

import (
	"gopkg.in/h2non/gentleman.v2/plugins/body"
	"gopkg.in/h2non/gentleman.v2/plugins/url"
)

const (
	groupsPath           = "/auth/admin/realms/:realm/groups"
	groupByIDPath        = "/auth/admin/realms/:realm/groups/:id"
	defaultGroupsPath    = "/auth/admin/realms/:realm/default-groups"
	defaultGroupByIDPath = "/auth/admin/realms/:realm/default-groups/:id"
)

// CreateGroup creates a new group for the realm
func (c *Client) CreateGroup(accessToken string, realmName string, group GroupRepresentation) (string, error) {
	return c.post(accessToken, nil, url.Path(groupsPath), url.Param("realm", realmName), body.JSON(group))
}

// DeleteGroup deletes a group from the realm
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

// GetDefaultGroups fetches the list of default groups for a realm
func (c *Client) GetDefaultGroups(accessToken string, realmName string) ([]GroupRepresentation, error) {
	resp := []GroupRepresentation{}
	err := c.get(accessToken, &resp, url.Path(defaultGroupsPath), url.Param("realm", realmName))
	return resp, err
}

// AddDefaultGroup places a new group for in the default realm groups by ID
func (c *Client) AddDefaultGroup(accessToken string, realmName string, groupID string) error {
	return c.put(accessToken, url.Path(defaultGroupByIDPath), url.Param("realm", realmName), url.Param("id", groupID))
}

// RemoveDefaultGroup deletes removes a group from the realm default groups list by ID
func (c *Client) RemoveDefaultGroup(accessToken string, realmName string, groupID string) error {
	return c.delete(accessToken, url.Path(defaultGroupByIDPath), url.Param("realm", realmName), url.Param("id", groupID))
}
