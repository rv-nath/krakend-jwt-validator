package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// Tests for the JWT Validator plugin
func TestJWTValidatorMiddleware(t *testing.T) {
	secret := "test-secret"
	jwtValidator := &JWTValidator{Secret: secret}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  1516239022,
	})
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	handler := func(_ context.Context, _ map[string]interface{}, next http.Handler) (http.Handler, error) {
		return jwtValidator.Middleware(next, []string{"/signup", "/welcome"}), nil
	}

	t.Run("Valid Token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		rec := httptest.NewRecorder()

		h, err := handler(context.Background(), nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "You have accessed a protected route!")
		}))
		if err != nil {
			t.Fatalf("Failed to create handler: %v", err)
		}

		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})

	t.Run("Missing Authorization Header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		rec := httptest.NewRecorder()

		h, err := handler(context.Background(), nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		if err != nil {
			t.Fatalf("Failed to create handler: %v", err)
		}

		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
		}
	})

	t.Run("Invalid Token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		rec := httptest.NewRecorder()

		h, err := handler(context.Background(), nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		if err != nil {
			t.Fatalf("Failed to create handler: %v", err)
		}

		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
		}
	})

	t.Run("Skip List - Signup Endpoint", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/signup", nil)
		rec := httptest.NewRecorder()

		h, err := handler(context.Background(), nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "Signup route - no JWT required!")
		}))
		if err != nil {
			t.Fatalf("Failed to create handler: %v", err)
		}

		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})

	t.Run("Skip List - Welcome Endpoint", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/welcome", nil)
		rec := httptest.NewRecorder()

		h, err := handler(context.Background(), nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "Welcome route - no JWT required!")
		}))
		if err != nil {
			t.Fatalf("Failed to create handler: %v", err)
		}

		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})
}
