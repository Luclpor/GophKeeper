package server

import "github.com/Luclpor/GophKeeper/internal/vault"

// AuthRequest is the JSON payload used for registration and login.
type AuthRequest struct {
	// Username is the user's login name.
	Username string `json:"username"`
	// Password is the plaintext password received over the HTTP request.
	Password string `json:"password"`
}

// AuthResponse is returned after successful registration or login.
type AuthResponse struct {
	// Username is the authenticated user's login name.
	Username string `json:"username"`
	// Token is the bearer token used for protected endpoints.
	Token string `json:"token"`
}

// ErrorResponse is the JSON shape used for HTTP errors.
type ErrorResponse struct {
	// Error contains a human-readable error message.
	Error string `json:"error"`
}

// SyncRequest contains records known by a client.
type SyncRequest struct {
	// Records is the client-side encrypted record set.
	Records []vault.Record `json:"records"`
}

// SyncResponse contains the merged server state for a user.
type SyncResponse struct {
	// Records is the server-side encrypted record set after merge.
	Records []vault.Record `json:"records"`
}
