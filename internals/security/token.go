package security

import (
	"fmt"
	"time"

	"github.com/Bigthugboy/wallet-project/internals"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
)

type WalletCliams struct {
	jwt.RegisteredClaims
	Email string
	ID    int64
}

var secretKey = []byte("404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970")

func Generate(email string, id int64) (string, string, error) {
	wClaims := WalletCliams{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "walletAdmin",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
		Email: email,
		ID:    id,
	}
	refWalletClaims := jwt.RegisteredClaims{
		Issuer:    "walletAdmin",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(48 * time.Hour)),
	}

	// Generate JWT tokens
	walletToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, wClaims).SignedString(secretKey)
	if err != nil {
		return "", "", err
	}
	refWalletToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refWalletClaims).SignedString(secretKey)
	if err != nil {
		return "", "", err
	}

	return walletToken, refWalletToken, nil
}

func Parse(tokenString string) (*WalletCliams, error) {
	token, err := jwt.ParseWithClaims(tokenString, &WalletCliams{}, func(t *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("error parsing token: %v", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*WalletCliams)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

func StoreSession(c *gin.Context, id int64, email, password string) error {
	userInfo := &internals.UserInfo{
		ID:       id,
		Email:    email,
		Password: password,
	}
	session := Sessions(c)
	session.Values["info"] = userInfo
	if err := session.Save(c.Request, c.Writer); err != nil {
		return fmt.Errorf("error saving session data: %v", err)
	}

	return nil
}

func Sessions(c *gin.Context) *sessions.Session {
	store := sessions.NewCookieStore([]byte("wallet"))
	session, _ := store.Get(c.Request, "session")
	return session
}
