package keycloak

import (
	"gopkg.in/h2non/gentleman.v2/plugins/url"
)

const (
	samlDescriptorPath = "/auth/realms/:realm/protocol/saml/descriptor"
)

// GetClientRoles gets all roles for the realm or client
func (c *Client) GetSAMLDescriptor(realmName string) (string, error) {
	req := c.httpClient.Get()
	resp, err := c.doRequest(req, url.Path(samlDescriptorPath), url.Param("realm", realmName))
	return resp.String(), err
}
