package jwt

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var secret = os.Getenv("JWT_SECRET")

func NewToken(userUUID, userEmail string, duration time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["uid"] = userUUID
	claims["email"] = userEmail
	claims["exp"] = time.Now().Add(duration).Unix()

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
