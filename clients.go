package keycloak

import (
	"fmt"

	"gopkg.in/h2non/gentleman.v2/plugins/body"
	"gopkg.in/h2non/gentleman.v2/plugins/url"
)

const (
	clientsPath  = "/auth/admin/realms/:realm/clients"
	clientIDPath = clientsPath + "/:id"
	clientSecret = clientIDPath + "/client-secret"
)

// GetClients returns a list of clients belonging to the realm.
// Parameters: clientId (filter by clientId),
// viewableOnly (filter clients that cannot be viewed in full by admin, default="false")
func (c *Client) GetClients(accessToken string, realmName string, paramKV ...string) ([]ClientRepresentation, error) {
	if len(paramKV)%2 != 0 {
		return nil, fmt.Errorf("the number of key/val parameters should be even")
	}

	var resp = []ClientRepresentation{}
	var plugins = append(createQueryPlugins(paramKV...), url.Path(clientsPath), url.Param("realm", realmName))
	var err = c.get(accessToken, &resp, plugins...)
	return resp, err
}

// GetClient get the representation of the client. idClient is the id of client (not client-id).
func (c *Client) GetClient(accessToken string, realmName, idClient string) (ClientRepresentation, error) {
	var resp = ClientRepresentation{}
	var err = c.get(accessToken, &resp, url.Path(clientIDPath), url.Param("realm", realmName), url.Param("id", idClient))
	return resp, err
}

// CreateClient creates a client
func (c *Client) CreateClient(accessToken string, realmName string, client ClientCreateRequest) (string, error) {
	return c.post(accessToken, nil, url.Path(clientsPath), url.Param("realm", realmName), body.JSON(client))
}

// UpdateClient updates the client.
func (c *Client) UpdateClient(accessToken string, realmName, clientID string, client ClientRepresentation) error {
	return c.put(accessToken, url.Path(clientIDPath), url.Param("realm", realmName), url.Param("id", clientID), body.JSON(client))
}

// GetSecret get the client secret. idClient is the id of client (not client-id).
func (c *Client) GetSecret(accessToken string, realmName, idClient string) (CredentialRepresentation, error) {
	var resp = CredentialRepresentation{}
	var err = c.get(accessToken, &resp, url.Path(clientSecret), url.Param("realm", realmName), url.Param("id", idClient))
	return resp, err
}

// DeleteClient deletes specified client from the realm. id is the id of client (not client-id).
func (c *Client) DeleteClient(accessToken string, realmName, id string) error {
	return c.delete(accessToken, url.Path(clientIDPath), url.Param("realm", realmName), url.Param("id", id))
}

// GetSAMLDescription gets the saml description for a client. idClient is the id of client (not client-id).
// GET https://id.tozny.com/auth/admin/realms/demorealm/clients/13be9337-b349-4e1a-9b1a-32fd227e0d0f/installation/providers/saml-idp-descriptor
// <?xml version="1.0" encoding="UTF-8"?>
// <EntityDescriptor entityID="https://id.tozny.com/auth/realms/demorealm"
//                    xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
//                    xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"
//                    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
//    <IDPSSODescriptor WantAuthnRequestsSigned="false"
//       protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
//       <SingleLogoutService
//          Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
//          Location="https://id.tozny.com/auth/realms/demorealm/protocol/saml" />
//       <SingleLogoutService
//          Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
//          Location="https://id.tozny.com/auth/realms/demorealm/protocol/saml" />
//    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
//    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
//    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>
//    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
//       <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
//          Location="https://id.tozny.com/auth/realms/demorealm/protocol/saml" />
//       <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
//          Location="https://id.tozny.com/auth/realms/demorealm/protocol/saml" />
//       <KeyDescriptor use="signing">
//         <dsig:KeyInfo>
//           <dsig:KeyName>xKHm8qTWp9Dppc6jOtcKkN8thWLSJ8OVHeVND7rH-1s</dsig:KeyName>
//           <dsig:X509Data>
//             <dsig:X509Certificate>MIICoTCCAYkCBgF1BX2OcTANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlkZW1vcmVhbG0wHhcNMjAxMDA3MjM1MzM1WhcNMzAxMDA3MjM1NTE1WjAUMRIwEAYDVQQDDAlkZW1vcmVhbG0wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCnwsBYFAnxrr36yjXen3+2LxuDqeBl7+qy+qkAOD91Pe7gokeY9aXkyQedb4kII37i6iPAwtCHg/PjwU3unufqB8hGmy/GTdq95u8DOrKcFDutNG8P/51qxGTDZVni5NzO6kchXSK/RHJgi47vbmPN7MzLZopuw2q1ulXmPkRYEGNALuW3Ofv8AwdvADRj7+Fq7VpIZmHsgMS+ujnnMYtISqENDP5qXAm+k2Ux69rgba5hNcFwwu9sipD+Ybc6MxtQxcKJh9ciPLoq+HYFpoF5uiBSzbgCZ7mrK/7/dZrrYC73+65ZGt6f0VHWMVjwpKUkqlCYOxGqRx7lrpZ967wfAgMBAAEwDQYJKoZIhvcNAQELBQADggEBABTSiOQ+Gi5Qer3nf7xoXbYuzv5/RwcilWOrnEmqLiM84nkH1nAiF0axDBFUv5NpqqEEb2VyyZz+pIfLiEhPwjpy03t24XLAz+S9CsQW7LNtfVobrf52dzofe/5NHymq2WtnBeOtt7HSgHVPUmTzBbA3HDKP5N4p359j32ElxcgSZOmC2IFNDcoVC39pylmTHuZ6MGOD6skeIANXxtU77HKPATLl9AkxOz7k5y+AiBJjsTmYxZVhhr72+8jyumeWq30K8SeO5CryU+JFvz5rljacZspGEgWoqaiqXxtENs9+K29lB1EB9delhSJkZ+u7gxQwkSTVYhkS6FZQfH2tuTE=</dsig:X509Certificate>
//           </dsig:X509Data>
//         </dsig:KeyInfo>
//       </KeyDescriptor>
//    </IDPSSODescriptor>
// </EntityDescriptor>
func (c *Client) GetSAMLDescription(accessToken string, realmName string, idClient string, format string) (string, error) {
	var description string
	path := c.apiURL.String() + "/auth/admin/realms/" + realmName + "/clients/" + idClient + "/installation/providers/" + format
	request, err := createVanillaRequest("GET", path, nil)
	if err != nil {
		return description, err
	}
	description, err = makePlainTextCall(accessToken, request)
	return description, err
}
