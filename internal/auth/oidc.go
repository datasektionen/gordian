package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type OIDCConfig struct {
	OAuth2Config oauth2.Config
	Verifier     *oidc.IDTokenVerifier
}

func InitOIDC(ctx context.Context, providerURL, clientID, clientSecret, redirectURL string) (*OIDCConfig, error) {
	provider, err := oidc.NewProvider(ctx, providerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "permissions"},
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	return &OIDCConfig{
		OAuth2Config: oauth2Config,
		Verifier:     verifier,
	}, nil
}

// parseAndValidateJWT parses and validates a JWT token string and extracts the subject and permissions
func parseAndValidateJWT(tokenString string, secretKey string) (sub string, permissions []string, err error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("there's an error with the signing method")
		}
		return []byte(secretKey), nil
	})

	if err != nil {
		return "", nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	if !token.Valid {
		return "", nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", nil, fmt.Errorf("failed to parse claims")
	}

	sub, ok = claims["sub"].(string)
	if !ok {
		return "", nil, fmt.Errorf("sub claim not found or invalid")
	}

	// Extract permissions from claims
	if permsInterface, ok := claims["permissions"]; ok {
		if permsList, ok := permsInterface.([]interface{}); ok {
			for _, p := range permsList {
				if permStr, ok := p.(string); ok {
					permissions = append(permissions, permStr)
				}
			}
		}
	}

	return sub, permissions, nil
}

// CheckAuth checks if user is authenticated without redirecting
func CheckAuth(r *http.Request, secretKey string) (string, []string, bool) {
	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value == "" {
		return "", nil, false
	}

	sub, perms, err := parseAndValidateJWT(cookie.Value, secretKey)
	if err != nil {
		return "", nil, false
	}

	return sub, perms, true
}

func Auth(w http.ResponseWriter, r *http.Request, oauth2Config oauth2.Config, secretKey string) (string, []string, error) {
	cookie, err := r.Cookie("session")

	if err != nil || cookie.Value == "" {
		// Redirect to login page which will handle secure state generation
		http.Redirect(w, r, "/login", http.StatusFound)
		return "", nil, err
	}

	sub, perms, err := parseAndValidateJWT(cookie.Value, secretKey)
	if err != nil {
		return "", nil, err
	}

	return sub, perms, nil
}

func CreateSessionToken(sub string, permissions []string, secretKey string) (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":         sub,
		"permissions": permissions,
		"iat":         now.Unix(),
		"nbf":         now.Unix(),
		"exp":         now.Add(7 * 24 * time.Hour).Unix(), // 7 days
	})

	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// CallbackHandler handles the OIDC callback
func (c *OIDCConfig) HandleCallback(ctx context.Context, r *http.Request) (string, error) {
	code := r.URL.Query().Get("code")
	if code == "" {
		return "", fmt.Errorf("no code in callback")
	}

	oauth2Token, err := c.OAuth2Config.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("failed to exchange token: %w", err)
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return "", fmt.Errorf("no id_token field in oauth2 token")
	}

	// Verify ID Token
	idToken, err := c.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return "", fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Extract custom claims
	var claims struct {
		Email    string `json:"email"`
		Username string `json:"preferred_username"`
		Sub      string `json:"sub"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return "", fmt.Errorf("failed to parse claims: %w", err)
	}

	// Return the subject (user identifier)
	if claims.Username != "" {
		return claims.Username, nil
	}
	if claims.Email != "" {
		return claims.Email, nil
	}
	return claims.Sub, nil
}

// GetPermissionsFromHive fetches permissions from Hive for the given user
func GetPermissionsFromHive(user, hiveURL, hiveToken string) ([]string, error) {
	req, err := http.NewRequest("GET", hiveURL+"/user/"+user+"/permissions", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for hive: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+hiveToken)

	// Use a client with timeout to prevent hanging requests
	client := &http.Client{Timeout: 15 * time.Second}
	userPerms, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("no response from hive: %w", err)
	}
	defer userPerms.Body.Close()

	if userPerms.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hive returned non-OK status: %d %s", userPerms.StatusCode, http.StatusText(userPerms.StatusCode))
	}

	type permObj struct {
		ID string `json:"id"`
	}

	var permObjs []permObj
	if err := json.NewDecoder(userPerms.Body).Decode(&permObjs); err != nil {
		return nil, fmt.Errorf("failed to decode perms body from json: %w", err)
	}

	perms := make([]string, len(permObjs))
	for i, p := range permObjs {
		perms[i] = p.ID
	}
	return perms, nil
}
