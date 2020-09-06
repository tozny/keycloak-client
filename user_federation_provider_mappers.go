package keycloak

import (
	"gopkg.in/h2non/gentleman.v2/plugins/body"
	"gopkg.in/h2non/gentleman.v2/plugins/url"
)

const (
	UserFederationProviderLDAPMapperType = "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"
)

// CreateUserFederationProviderMapper creates a user federation provider mapper for a realm for mapping attributes from
// synced users from an external source, returning the location of the created provider mapper or error (if any).
func (c *Client) CreateUserFederationProviderMapper(accessToken string, realmName string, userFederationProviderMapper UserFederationProviderMapperRepresentation) (string, error) {
	return c.post(accessToken, nil, url.Path(componentsPath), url.Param("realm", realmName), body.JSON(userFederationProviderMapper))
}

// GetUserFederationProviderMappers returns a list of UserFederationProviderMappers belonging to the realm
// or error (if any).
func (c *Client) GetUserFederationProviderMappers(accessToken string, realmName string, userFederationProviderID string, mapperType string) ([]UserFederationProviderMapperRepresentation, error) {
	resp := []UserFederationProviderMapperRepresentation{}

	queryParams := []string{
		"parent", userFederationProviderID,
		"type", mapperType,
	}

	plugins := append(createQueryPlugins(queryParams...), url.Path(componentsPath), url.Param("realm", realmName))

	err := c.get(accessToken, &resp, plugins...)

	return resp, err
}

// GetUserFederationProviderMapper returns the representation of the specified UserFederationProviderMapper or error (if any).
func (c *Client) GetUserFederationProviderMapper(accessToken string, realmName, userFederationProviderMapperID string) (UserFederationProviderMapperRepresentation, error) {
	resp := UserFederationProviderMapperRepresentation{}

	err := c.get(accessToken, &resp, url.Path(componentsIDPath), url.Param("realm", realmName), url.Param("id", userFederationProviderMapperID))

	return resp, err
}

// UpdateUserFederationProviderMapper updates the UserFederationProviderMapper.
func (c *Client) UpdateUserFederationProviderMapper(accessToken string, realmName, userFederationProviderMapperID string, userFederationProviderMapper UserFederationProviderMapperRepresentation) error {
	return c.put(accessToken, url.Path(componentsIDPath), url.Param("realm", realmName), url.Param("id", userFederationProviderMapperID), body.JSON(userFederationProviderMapper))
}

// DeleteUserFederationProviderMapper deletes the specified UserFederationProviderMapper from the realm.
func (c *Client) DeleteUserFederationProviderMapper(accessToken string, realmName, userFederationProviderMapperID string) error {
	return c.delete(accessToken, url.Path(componentsIDPath), url.Param("realm", realmName), url.Param("id", userFederationProviderMapperID))
}
