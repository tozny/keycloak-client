package keycloak

import (
	"gopkg.in/h2non/gentleman.v2/plugins/url"
)

const (
	samlDescriptorPath = "/auth/realms/:realm/protocol/saml/descriptor"
)

// GetSAMLDescriptor fetches the public XML IDP descriptor document for a realm
func (c *Client) GetSAMLDescriptor(realmName string) (string, error) {
	req := c.httpClient.Get()
	resp, err := c.doRequest(req, url.Path(samlDescriptorPath), url.Param("realm", realmName))
	return resp.String(), err
}
