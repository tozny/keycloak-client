package keycloak

import (
	"gopkg.in/h2non/gentleman.v2/plugins/body"
	"gopkg.in/h2non/gentleman.v2/plugins/url"
)

const (
	componentsPath             = "/auth/admin/realms/:realm/components"
	componentsIDPath           = componentsPath + "/:id"
	UserFederationProviderType = "org.keycloak.storage.UserStorageProvider"
)

// CreateUserFederationProvider creates a user federation provider for a realm for syncing users from an external source,
// returning the location of the created provider or error (if any).
func (c *Client) CreateUserFederationProvider(accessToken string, realmName string, userFederationProvider UserFederationProviderRepresentation) (string, error) {
	return c.post(accessToken, nil, url.Path(componentsPath), url.Param("realm", realmName), body.JSON(userFederationProvider))
}

// GetUserFederationProviders returns a list of UserFederationProviders belonging to the realm
// or error (if any).
func (c *Client) GetUserFederationProviders(accessToken string, realmName string, realmId string) ([]UserFederationProviderRepresentation, error) {
	resp := []UserFederationProviderRepresentation{}

	queryParams := []string{
		"parent", realmId,
		"type", UserFederationProviderType,
	}

	plugins := append(createQueryPlugins(queryParams...), url.Path(componentsPath), url.Param("realm", realmName))

	err := c.get(accessToken, &resp, plugins...)

	return resp, err
}

// GetUserFederationProvider returns the representation of the specified UserFederationProvider or error (if any).
func (c *Client) GetUserFederationProvider(accessToken string, realmName, userFederationProviderID string) (UserFederationProviderRepresentation, error) {
	resp := UserFederationProviderRepresentation{}

	err := c.get(accessToken, &resp, url.Path(componentsIDPath), url.Param("realm", realmName), url.Param("id", userFederationProviderID))

	return resp, err
}

// UpdateUserFederationProvider updates the UserFederationProvider.
func (c *Client) UpdateUserFederationProvider(accessToken string, realmName, userFederationProviderID string, userFederationProvider UserFederationProviderRepresentation) error {
	return c.put(accessToken, url.Path(componentsIDPath), url.Param("realm", realmName), url.Param("id", userFederationProviderID), body.JSON(userFederationProvider))
}

// DeleteUserFederationProvider deletes the specified UserFederationProvider from the realm.
func (c *Client) DeleteUserFederationProvider(accessToken string, realmName, userFederationProviderID string) error {
	return c.delete(accessToken, url.Path(componentsIDPath), url.Param("realm", realmName), url.Param("id", userFederationProviderID))
}
