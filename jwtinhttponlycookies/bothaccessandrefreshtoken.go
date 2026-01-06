package jwtinhttponlycookies

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

type Claims1 struct {
	Email     string `json:"email"`
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

type Credentials1 struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

const (
	accesstokenTTL  = 15 * time.Minute
	refreshtokenTTL = 7 * 24 * time.Hour
)

var SecretKey1 []byte

func GenerateAccessToken(email string) (string, error) {
	claims := &Claims1{
		Email:     email,
		TokenType: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(accesstokenTTL)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(SecretKey1)
}

func GenerateRefreshToken(email string) (string, error) {
	claims := &Claims1{
		Email:     email,
		TokenType: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(refreshtokenTTL)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(SecretKey1)
}

func ValidateJWT1(tokenstr string) (*Claims1, error) {
	token, err := jwt.ParseWithClaims(tokenstr, &Claims1{}, func(t *jwt.Token) (interface{}, error) {
		return SecretKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token %v", err)
	}
	claims, ok := token.Claims.(*Claims1)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("Token not valid!")
	}
	return claims, nil

}
func SetAccessCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    token,
		HttpOnly: true,
		Secure:   false,
		Path:     "/",
		Expires:  time.Now().Add(accesstokenTTL),
		SameSite: http.SameSiteStrictMode,
	})
}
func SetRefreshCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    token,
		HttpOnly: true,
		Secure:   false,
		Path:     "/",
		Expires:  time.Now().Add(refreshtokenTTL),
		SameSite: http.SameSiteStrictMode,
	})
}
func ClearAccessCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    "",
		HttpOnly: true,
		Path:     "/",
		Expires:  time.Now().Add(-time.Hour),
	})
}

func LoginHandler1(w http.ResponseWriter, r *http.Request) {
	var creds Credentials1
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "failed to decode response", http.StatusUnauthorized)
		return
	}
	if creds.Email != "akash@gmail.com" || creds.Password != "Akash@123" {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	accesstoken, _ := GenerateAccessToken(creds.Email)
	refreshtoken, _ := GenerateRefreshToken(creds.Email)

	SetAccessCookie(w, accesstoken)
	SetRefreshCookie(w, refreshtoken)

	json.NewEncoder(w).Encode(map[string]string{"message": "login succesful!"})
}

// JWTMiddleware
func JWTMiddleware1(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("access_token")
		if err != nil {
			http.Error(w, "Not authenticated", http.StatusUnauthorized)
			return
		}
		tokrnstr := cookie.Value

		claims, err := ValidateJWT1(tokrnstr)
		if err != nil {
			http.Error(w, "invalid cookie", http.StatusUnauthorized)
			return
		}
		if claims.TokenType != "access" {
			http.Error(w, "Invalid token!", http.StatusUnauthorized)
			return
		}
		r.Header.Set("X-User-Email", claims.Email)

		next.ServeHTTP(w, r)
	}
}

func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		http.Error(w, "refresh token missing", http.StatusUnauthorized)
		return
	}
	claims := &Claims1{}
	token, err := jwt.ParseWithClaims(cookie.Value, claims, func(t *jwt.Token) (interface{}, error) {
		return SecretKey1, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}
	if claims.TokenType != "refresh" {
		http.Error(w, "Wrong token type", http.StatusUnauthorized)
		return
	}
	newaccess, _ := GenerateAccessToken(claims.Email)

	SetAccessCookie(w, newaccess)

	json.NewEncoder(w).Encode(map[string]string{"message": "new access token issued via refresh token", "access_token": newaccess})
}

// Logout
func LogoutHandler1(w http.ResponseWriter, r *http.Request) {
	ClearAccessCookie(w)

	json.NewEncoder(w).Encode(map[string]string{"message": "Logout succesful!"})
}

// main function
func BothAccessAndRefreshToken() {
	godotenv.Load()

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatalf("JWT_SECRET is empty or not set")
	}
	SecretKey1 = []byte(secret)

	r := http.NewServeMux()

	r.HandleFunc("/login", LoginHandler1)
	r.HandleFunc("/refresh", RefreshHandler)
	r.HandleFunc("/logout", LogoutHandler1)

	fmt.Println("Server running on port:8080")
	http.ListenAndServe(":8080", r)

}
