package jwt

import (
	"sso/internal/domain/models"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNewToken(t *testing.T) {
	testTable := []struct {
		app      models.App
		user     models.User
		duration time.Duration
	}{
		{
			app: models.App{
				ID:     1,
				Secret: "secretNumber1",
			},
			user: models.User{
				UUID:  uuid.New(),
				Email: "testemail1@proton.me",
			},
			duration: time.Hour,
		},
		{
			app: models.App{
				ID:     2,
				Secret: "39848ilIUO3J89AJ4389lkj",
			},
			user: models.User{
				UUID:  uuid.New(),
				Email: "invalidtestmail",
			},
			duration: time.Hour,
		},
	}

	for _, testCase := range testTable {
		tokenString, err := NewToken(testCase.user, testCase.duration)

		t.Logf("calling NewToken(\nuserid:%d\nemail:%s\n),result %s\n", testCase.user.UUID.ID(), testCase.user.Email, tokenString)
		if err != nil {
			t.Errorf("failed to create jwt,error:%v", err)
		} else if tokenString == "" {
			t.Errorf("token string is empty")
		}
	}
}
