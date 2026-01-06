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

type Claims struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
	jwt.RegisteredClaims
}

type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

var SecretKey []byte

func GenerateJWT(UserID int, email string) (string, error) {
	claims := &Claims{
		ID:    UserID,
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "Campus central auth",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(SecretKey)
}

func ValidateJWT(tokenstr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenstr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return SecretKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token %v", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("token not valid ")
	}
	return claims, nil
}

// Set jwt cookie
func SetJWTCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    token,
		HttpOnly: true,
		Secure:   false,
		Path:     "/",
		Expires:  time.Now().Add(15 * time.Minute),
		SameSite: http.SameSiteStrictMode,
	})
}

// Clear jwt cookie
func ClearJWTCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    "",
		HttpOnly: true,
		Path:     "/",
		Expires:  time.Now().Add(-time.Hour),
	})
}

// JWTCookieMiddleware
func JwtCookieMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("access_token")
		if err != nil {
			http.Error(w, "not authenticated", http.StatusUnauthorized)
			return
		}
		tokenstr := cookie.Value

		claims, err := ValidateJWT(tokenstr)
		if err != nil {
			http.Error(w, "invalid or expired jwt cookie", http.StatusUnauthorized)
			return
		}
		r.Header.Set("X-User-Email", claims.Email)

		next.ServeHTTP(w, r)
	}
}

// Handlers
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Failed to decode response", http.StatusInternalServerError)
		return
	}
	if creds.Email != "akash@gmail.com" || creds.Password != "Akash@123" {
		http.Error(w, "Invalid crediantials", http.StatusUnauthorized)
		return
	}
	// create JWT after succesful login
	token, err := GenerateJWT(1, creds.Email)
	if err != nil {
		http.Error(w, "failed to generate JWT", http.StatusUnauthorized)
		return
	}
	SetJWTCookie(w, token) // sttore JWT in cookie

	json.NewEncoder(w).Encode(map[string]string{"message": "login succesful!"})
}

// Logout
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	ClearJWTCookie(w)

	w.Write([]byte("Logout succesful!"))
}

// main func

func JWTCookie() {
	godotenv.Load()
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatalf("JWT_SECRET is not set or empty")
	}
	SecretKey = []byte(secret)

	r := http.NewServeMux()

	r.HandleFunc("/login", LoginHandler)
	r.HandleFunc("/logout", LogoutHandler)

	fmt.Println("Server running on port:8080")
	http.ListenAndServe(":8080", r)
}
