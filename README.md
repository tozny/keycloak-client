## Basic keycloak client in go

This repo provides a basic keycloak client in go.

## Keycloak API Version Compatibility

The keycloak client in this repo is valid for the [Keycloak API @v4.8.3.Final](https://www.keycloak.org/docs-api/4.8/rest-api/index.html)

## Tokens and Refreshing

The client will fetch tokens based a realm and user credentials (username/password). The token fetched by the client will get cached in memory. On each use, the client will verify the cached token is still valid and if necessary, extend the session using the refresh token, or establish a new session using the provided credentials.

### Automatic refreshing

If you would like to ensure the token cache is always warm, you can enable auto-refreshing. When the client's auth token is 5 seconds from expiration, a background process will refresh the token either by extending the session using the refresh token, or establishing a nw session using the provided credentials.

When starting automatic refresh, provide a method to handle errors when the refresh fails. This method could organize retries, panic, log the
error and move on, etc. Whatever makes sense for the application using the client.

```go
realm := "example"
username := "admin"
password := "secret"
func onFailure(err error) {
	log.Printf("Unable to auto refresh token: %v. Retrying...", err)
	// Retry after 30 seconds
	time.AfterFunc(30 * time.Second, func(){
		log.Print("Retrying auto refresh of Keycloak token")
		client.AutoRefreshToken(realm, username, password, onFailure)
	})
}
client.AutoRefreshToken(realm, username, password, onFailure)
```
