package jwt

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	secret          = os.Getenv("JWT_SECRET")
	ErrInvalidToken = errors.New("invalid token")
)

type contextKey string

const (
	UserIDKey contextKey = "userID"
)

type Claims struct {
	UserID string `json:"uid"`
	Exp    int64  `json:"exp"`
}

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

func GetUserID(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(UserIDKey).(string)
	return userID, ok
}

func ParseToken(tokenString, secret string) (*Claims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}

	claims, _ := token.Claims.(jwt.MapClaims)
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, ErrInvalidToken
	}
	if time.Now().Unix() > int64(exp) {
		return nil, ErrInvalidToken
	}

	uID, ok := claims["uid"].(string)
	if !ok {
		return nil, ErrInvalidToken
	}
	return &Claims{
		UserID: uID,
		Exp:    int64(exp),
	}, nil
}
