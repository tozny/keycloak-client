package keycloak

import (
	"gopkg.in/h2non/gentleman.v2/plugins/body"
	"gopkg.in/h2non/gentleman.v2/plugins/url"
)

const (
	protocolMappersByProtocolPath            = "/auth/admin/realms/:realm/clients/:client_id/protocol-mappers/protocol/:protocol"
	protocolMappersPath                      = "/auth/admin/realms/:realm/clients/:client_id/protocol-mappers/models"
	protocolMapperByIDPath                   = protocolMappersPath + "/:id"
	UserSessionNoteOIDCApplicationMapperType = "oidc-usersessionmodel-note-mapper"
	UserAttributeOIDCApplicationMapperType   = "oidc-usermodel-attribute-mapper"
	RoleListSAMLApplicationMapperType        = "saml-role-list-mapper"
	UserPropertySAMLApplicationMapperType    = "saml-user-property-mapper"
)

// CreateProtocolMapper creates a new protocol mapper for the client
func (c *Client) CreateProtocolMapper(accessToken string, realmName string, clientId string, protocolMapper ProtocolMapperRepresentation) (string, error) {
	return c.post(accessToken, nil, url.Path(protocolMappersPath), url.Param("realm", realmName), url.Param("client_id", clientId), body.JSON(protocolMapper))
}

// DeleteProtocolMapper deletes a protocol mapper from the client
func (c *Client) DeleteProtocolMapper(accessToken string, realmName string, clientId string, protocolMapperID string) error {
	return c.delete(accessToken, url.Path(protocolMapperByIDPath), url.Param("realm", realmName), url.Param("client_id", clientId), url.Param("id", protocolMapperID))
}

// GetProtocolMappers gets all mappers of a given protocol for the client
func (c *Client) GetProtocolMappers(accessToken string, realmName string, clientId string, protocol string) ([]ProtocolMapperRepresentation, error) {
	var resp = []ProtocolMapperRepresentation{}
	var err = c.get(accessToken, &resp, url.Path(protocolMappersByProtocolPath), url.Param("realm", realmName), url.Param("client_id", clientId), url.Param("protocol", protocol))
	return resp, err
}

// GetProtocolMapper gets a specific protocol mapper’s representation
func (c *Client) GetProtocolMapper(accessToken string, realmName string, clientId string, protocolmapperID string) (ProtocolMapperRepresentation, error) {
	var resp = ProtocolMapperRepresentation{}
	var err = c.get(accessToken, &resp, url.Path(protocolMapperByIDPath), url.Param("realm", realmName), url.Param("client_id", clientId), url.Param("id", protocolmapperID))
	return resp, err
}
