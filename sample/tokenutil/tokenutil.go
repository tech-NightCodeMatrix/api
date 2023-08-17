package tokenutil

import (
	"errors"
	"fmt"
	"sample/domain"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

var Users = map[string]string{
	"username": "testuser",
	"password": "password",
	"phone":    "1237484924",
	"id":       "1999",
}

func CreateAccessToken(user *domain.User, secret string, expiry int) (accessToken string, err error) {
	exp := jwt.NewNumericDate(time.Now().Add(time.Hour * time.Duration(expiry)))
	//info := Users["username"]
	id := Users["id"]
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["expires"] = exp
	//claims["info"] = info
	claims["id"] = id
	t, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return t, err
}

func IsAuthorized(requestToken string, secret string) (bool, error) {
	var verify string
	token, err := jwt.Parse(requestToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return false, err
	}
	if !token.Valid {
		return false, errors.New("token is invalid")
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		verify = fmt.Sprint(claims["info"])
	}
	if verify == "" {
		return true, fmt.Errorf("invalid token payload")
	}
	return true, nil

}

// func ExtractIDFromToken(requestToken string, secret string) (string, error) {
// 	token, err := jwt.Parse(requestToken, func(token *jwt.Token) (interface{}, error) {
// 		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
// 			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
// 		}
// 		return []byte(secret), nil
// 	})

// 	if err != nil {
// 		return "", err
// 	}

// 	claims, ok := token.Claims.(jwt.MapClaims)

// 	if !ok && !token.Valid {
// 		return "", fmt.Errorf("invalid Token")
// 	}

// 	return claims["id"].(string), nil
// }
