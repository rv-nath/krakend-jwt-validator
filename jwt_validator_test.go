package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// Tests for the JWT Validator plugin
func TestJWTValidatorMiddleware(t *testing.T) {
	secret := "test-secret"

	// Generate RSA keys
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA private key: %v", err)
	}

	// Create a mock JWKS Server
	jwksServer, jwksURL := createMockJWKS(privateKey)
	defer jwksServer.Close()

	// Create a new JWTValidator instance and provide the required configuration
	pluginConfig := map[string]interface{}{
		"krakend-jwt-validator": map[string]interface{}{
			"shared_secret": secret,
			"jwks_url":      jwksURL,
		},
	}
	handlerRegisterer := registerer(pluginName)

	jwtValidatorHandler, err := handlerRegisterer.registerHandlers(context.Background(), pluginConfig, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "You have accessed a protected route!")
	}))
	if err != nil {
		t.Fatalf("Failed to register JWT validator handler: %v", err)
	}

	t.Run("Valid HMAC Token", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub":  "1234567890",
			"name": "John Doe",
			"iat":  1516239022,
		})
		tokenString, err := token.SignedString([]byte(secret))
		if err != nil {
			t.Fatalf("Failed to sign token: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		rec := httptest.NewRecorder()

		jwtValidatorHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})

	t.Run("Missing Authorization Header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		rec := httptest.NewRecorder()

		jwtValidatorHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
		}
	})

	t.Run("Invalid Token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		rec := httptest.NewRecorder()

		jwtValidatorHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
		}
	})

	t.Run("Valid RSA Token", func(t *testing.T) {
		// Create RSA signed token
		claims := jwt.MapClaims{
			"sub":  "1234567890",
			"name": "Jane Doe",
			"iat":  1516239022,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["Kid"] = "test-key"
		tokenString, err := token.SignedString(privateKey)
		if err != nil {
			t.Fatalf("Failed to sign token with RSA private key: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		rec := httptest.NewRecorder()

		jwtValidatorHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})
}

// Helper function to convert int to byte slice (for RSA exponent)
func intToBytes(i uint32) []byte {
	var bytes []byte
	for i > 0 {
		bytes = append([]byte{byte(i & 0xff)}, bytes...)
		i >>= 8
	}
	return bytes
}

// Helper function to create a mock JWKS server
func createMockJWKS(privateKey *rsa.PrivateKey) (*httptest.Server, string) {
	publicKey := &privateKey.PublicKey

	// Encode the public key to PEM format
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	})

	// Mock JWKS response
	jwks := JWKS{
		Keys: []JSONWebKey{
			{
				Kid: "test-key",
				Kty: "RSA",
				Alg: "RS256",
				Use: "sig",
				N:   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(intToBytes(uint32(publicKey.E))),
				// X5c: []string{base64.StdEncoding.EncodeToString(pubKeyPEM)},
				X5c: []string{string(pubKeyPEM)},
			},
		},
	}

	// Create a dummy HTTP server that serves the JWKS
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Mock server executing Request contest: %v ", r.Context())
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
		fmt.Printf("Done with the mock server")
	}))

	return jwksServer, jwksServer.URL
}
