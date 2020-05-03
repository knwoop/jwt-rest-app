package main

import (
	"fmt"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

var mySigningKey = []byte(os.Getenv("MY_JWT_TOKEN"))

func GenerateJWT() (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true
	claims["user"] = "knwoop"
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	tokenString, err := token.SignedString(mySigningKey)
	if err != nil {
		return "", fmt.Errorf("error token.SignedString: %w", err)
	}
	return tokenString, nil
}

func main() {
	fmt.Println("My simple client")

	token, err := GenerateJWT()
	if err != nil {
		fmt.Println("Error generating token string")
	}

	fmt.Println(token)
}
