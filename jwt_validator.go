package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"
)

var (
	pluginName        = "krakend-jwt-validator"
	HandlerRegisterer = registerer(pluginName)
)

type registerer string

func (r registerer) RegisterHandlers(f func(
	name string,
	handler func(context.Context, map[string]interface{}, http.Handler) (http.Handler, error),
),
) {
	f(string(r), r.registerHandlers)
}

func (r registerer) registerHandlers(_ context.Context, extra map[string]interface{}, h http.Handler) (http.Handler, error) {
	// If the plugin requires some configuration, it should be under the name of the plugin.
	cfg, ok := extra[pluginName].(map[string]interface{})
	if !ok {
		return nil, errors.New("configuration not found for jwt validator")
	}

	// Get the secret from the configuration
	secret, ok := cfg["shared_secret"].(string)
	if !ok {
		logger.Info(fmt.Sprintf("[PLUGIN: %s] Missing secret in configuration. Will not handle HMAC signed JWTs.", HandlerRegisterer))
		// return h, errors.New("missing jwt secret in configuration")
	}

	// Get JWKS URL from the configuration
	jwksURL, ok := cfg["jwks_url"].(string)
	if !ok {
		logger.Info(fmt.Sprintf("[PLUGIN: %s] Missing jwksURL in configuration. Will not handle RSA signed JWTs.", HandlerRegisterer))
		// return h, errors.New("missing `` in configuration")
	}

	// Check if at least one of the secret or jwksURL is provided
	if secret == "" && jwksURL == "" {
		logger.Error(fmt.Sprintf("[PLUGIN: %s] At least either `shared_secret` or `jwks_url` must be provided in krakend.json", HandlerRegisterer))
		return nil, errors.New("Either jwt secret or jwksURL is required")
	}

	// Inititalize the JWTValidator struct
	jwtValidator := &JWTValidator{Secret: secret, jwksURL: jwksURL}

	logger.Debug(fmt.Sprintf("[PLUGIN: %s] JWT validator middleware registered.", HandlerRegisterer))
	return jwtValidator.Middleware(h), nil
}

// JWTValidator is a struct that holds the shared secret
type JWTValidator struct {
	Secret  string
	jwksURL string
	jwks    *JWKS
	sync.RWMutex
}

// JWKS is a struct that holds the JSON Web Key Set
type JWKS struct {
	Keys []JSONWebKey `json:"keys"`
}

// JSONWebKey represents a single key in the JWKS
type JSONWebKey struct {
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	Alg string   `json:"alg"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

/*
 * Fetches the JWKS data from the JWKS URL and stores it in the JWTValidator struct
 */
func (j *JWTValidator) fetchJWKS() error {
	resp, err := http.Get(j.jwksURL)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch JWKS: received status code %v", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS: %v", err)
	}

	j.Lock()
	j.jwks = &jwks
	j.Unlock()

	return nil
}

// ValidateJWT validates the incoming JWT token
func (j *JWTValidator) ValidateJWT(tokenString string) (jwt.MapClaims, error) {
	// Decode the token header without validating the signature
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token header: %v", err)
	}

	// Extract algorithm from token header
	alg := token.Header["alg"]
	switch alg {
	case "HS256":
		// Validate with HMAC secret
		return j.validateWithHMAC(tokenString)
	case "RS256":
		// Validate with RSA public key from JWKS
		return j.validateWithRSA(tokenString)
	default:
		return nil, fmt.Errorf("unsupported signing method: %v", alg)
	}
}

// If the token is signed with validateWithHMAC method then validate the token with HMAC Secret
func (j *JWTValidator) validateWithHMAC(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(j.Secret), nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, fmt.Errorf("invalid token")
	}
}

// If the token is signed with validateWithRSA method then validate the token with RSA Public Key
func (j *JWTValidator) validateWithRSA(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Use JWKS URL to get the public key
		keyFunc, err := j.getKeyFromJWKS(token)
		if err != nil {
			return nil, err
		}
		return keyFunc, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		logger.Debug(fmt.Sprintf("[PLUGIN: %s] Token is valid.  Good to go...", HandlerRegisterer))
		return claims, nil
	} else {
		return nil, fmt.Errorf("invalid token")
	}
}

// Retrieves the RSA public key from the JWKS using the "kid" in the token header,
// optionally fetching the JWKS from the URL if it's not already cached
func (j *JWTValidator) getKeyFromJWKS(token *jwt.Token) (interface{}, error) {
	j.RLock()
	if j.jwks != nil {
		for _, key := range j.jwks.Keys {
			if key.Kid == token.Header["kid"] {
				return parseRSAPublicKey(&key)
			}
		}
	}
	j.RUnlock()

	// Fetch the JWKS from the URL
	logger.Debug(fmt.Sprintf("[PLUGIN: %s] Fetching JWKS from URL: %v ", HandlerRegisterer, j.jwksURL))
	resp, err := http.Get(j.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %v", err)
	}
	defer resp.Body.Close()
	logger.Debug(fmt.Sprintf("[PLUGIN: %s] Finished fetching JWKS from URL %v ", HandlerRegisterer, j.jwksURL))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch JWKS: received status code %v", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %v", err)
	}

	j.Lock()
	j.jwks = &jwks
	j.Unlock()
	// printJWKS(j.jwks)

	j.RLock()
	defer j.RUnlock()
	// Find the key that matches the "kid" in the token header
	logger.Debug(fmt.Sprintf("[PLUGIN: %s] Found kid value in token: %v ", HandlerRegisterer, token.Header["kid"]))
	for _, key := range jwks.Keys {
		if key.Kid == token.Header["kid"] {
			logger.Debug(fmt.Sprintf("[PLUGIN: %s] Match found for kid in jwks for %v ", HandlerRegisterer, token.Header["kid"]))
			return parseRSAPublicKey(&key)
		}
	}

	return nil, fmt.Errorf("no matching key found in JWKS for kid: %v", token.Header["kid"])
}

// parseRSAPublicKey parses a JSONWebKey into an RSA public key
func parseRSAPublicKey(jwk *JSONWebKey) (interface{}, error) {
	if jwk.N == "" || jwk.E == "" {
		return nil, fmt.Errorf("modulus or exponent is missing in JWKS for key ID: %s", jwk.Kid)
	}
	// Decode the modulus (N) and exponent (E) from base64
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus from JWKS: %v", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent from JWKS: %v", err)
	}
	// Convert exponent bytes to integer
	eInt := 0
	for _, b := range eBytes {
		eInt = (eInt << 8) | int(b)
	}

	// Create the RSA public key
	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}

	return pubKey, nil
}

// Middleware function that validates the JWT token and enriches the request with claims
func (j *JWTValidator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Logging
		logger.Info(fmt.Sprintf("[PLUGIN: %s] Middleware executing..matching.", HandlerRegisterer))

		// print the request context
		logger.Debug(fmt.Sprintf("[PLUGIN: %s] Request contest: %v ", HandlerRegisterer, r.Context()))

		// Check if the bypassValidation field is available in the context
		if bypass, ok := r.Context().Value("bypassValidation").(bool); ok && bypass {

			logger.Info(fmt.Sprintf("[PLUGIN: %s] Bypassing validation based on context flag.", HandlerRegisterer))
			next.ServeHTTP(w, r)
			return
		}

		// Core logic of this plugin (validate jwt)
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}

		// Extract the token string (expecting a Bearer token)
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, "invalid Authorization format", http.StatusUnauthorized)
			return
		}
		tokenString := parts[1]

		// Validate the token
		claims, err := j.ValidateJWT(tokenString)
		if err != nil {
			fmt.Println("JWT Validation error:", err)
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		// Add the claims to the request context for downstream handlers
		ctx := r.Context()
		for key, value := range claims {
			ctx = context.WithValue(ctx, key, value)
		}
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func main() {}

// This logger is replaced by the RegisterLogger method to load the one from krakenD.
var logger Logger = noopLogger{}

func (registerer) RegisterLogger(v interface{}) {
	l, ok := v.(Logger)
	if !ok {
		return
	}
	logger = l
	logger.Debug(fmt.Sprintf("[PLUGIN: %s] Logger loaded", HandlerRegisterer))
}

type Logger interface {
	Debug(v ...interface{})
	Info(v ...interface{})
	Warning(v ...interface{})
	Error(v ...interface{})
	Critical(v ...interface{})
	Fatal(v ...interface{})
}

// Empty logger implementation
type noopLogger struct{}

func (n noopLogger) Debug(_ ...interface{})    {}
func (n noopLogger) Info(_ ...interface{})     {}
func (n noopLogger) Warning(_ ...interface{})  {}
func (n noopLogger) Error(_ ...interface{})    {}
func (n noopLogger) Critical(_ ...interface{}) {}
func (n noopLogger) Fatal(_ ...interface{})    {}

/*
func printJWKS(jwks *JWKS) {
	for _, key := range jwks.Keys {
		fmt.Printf("Key ID: %v\n", key.Kid)
		fmt.Printf("Key Type: %v\n", key.Kty)
		fmt.Printf("Algorithm: %v\n", key.Alg)
		fmt.Printf("Use: %v\n", key.Use)
		fmt.Printf("Modulus: %v\n", key.N)
		fmt.Printf("Exponent: %v\n", key.E)
		fmt.Printf("Certificate: %v\n", key.X5c)
	}
}
*/
