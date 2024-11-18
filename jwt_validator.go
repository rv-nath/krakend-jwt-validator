package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

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
		return h, errors.New("configuration not found for jwt validator")
	}

	// Extract exceptions list from configuration
	logger.Debug("Extracting exceptions from configuration...")
	exceptions, _ := cfg["exceptions"].([]interface{})
	exceptionURLs := make([]string, len(exceptions))
	for i, url := range exceptions {
		exceptionURLs[i] = url.(string)
	}

	// Get the secret from the configuration
	secret, ok := cfg["secret"].(string)
	if !ok {
		return h, errors.New("missing jwt secret in configuration")
	}

	jwtValidator := &JWTValidator{Secret: secret}

	return jwtValidator.Middleware(h, exceptionURLs), nil
}

// JWTValidator is a struct that holds the shared secret
type JWTValidator struct {
	Secret string
}

// ValidateJWT validates the incoming JWT token using the shared secret
func (j *JWTValidator) ValidateJWT(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is HMAC (for shared secret)
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(j.Secret), nil
	})
	// Check if an error occurred during parsing
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenMalformed):
			fmt.Println("That's not even a token")
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			fmt.Println("Invalid signature")
		case errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet):
			fmt.Println("Timing is everything")
		default:
			fmt.Println("Couldn't handle this token:", err)
		}
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, fmt.Errorf("invalid token")
	}
}

// Middleware function that validates the JWT token and enriches the request with claims
func (j *JWTValidator) Middleware(next http.Handler, exceptionURLs []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Logging
		logger.Debug(fmt.Sprintf("[PLUGIN: %s] Middleware executing..", HandlerRegisterer))

		// Skip validation if the URL is in the exceptions list
		for _, exception := range exceptionURLs {
			if strings.HasPrefix(r.URL.Path, exception) {
				next.ServeHTTP(w, r)
				return
			}
		}

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
