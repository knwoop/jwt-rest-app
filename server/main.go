package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

var mySigningKey = []byte(os.Getenv("MY_JWT_TOKEN"))

func homePage(w http.ResponseWriter, r *http.Request) {
	auth, err := Parse(r.Header["Token"][0])
	if err != nil {
		fmt.Fprintf(w, "%s", err)
		return
	}
	fmt.Fprintf(w, "userid: %s\n", auth.UserID)
	fmt.Fprintf(w, "Super Secret Information\n")

}

func isAuthorized(endpoint func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header["Token"] != nil {
			token, err := jwt.Parse(r.Header["Token"][0], func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				return mySigningKey, nil
			})

			if err != nil {
				fmt.Fprintf(w, err.Error())
			}

			if token.Valid {
				endpoint(w, r)
			}
		} else {
			fmt.Fprintf(w, "Not Authorized")
		}
	})
}

const (
	userKey  = "user"
	expKey   = "exp"
	lifetime = 30 * time.Minute
)

type Auth struct {
	UserID string
}

func Parse(signedString string) (*Auth, error) {
	token, err := jwt.Parse(signedString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return "", fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return mySigningKey, nil
	})

	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorExpired != 0 {
				return nil, fmt.Errorf("%s is expired: %w", signedString, err)
			} else {
				return nil, fmt.Errorf("%s is invalid: %w", signedString, err)
			}
		} else {
			return nil, fmt.Errorf("%s is invalid: %w", signedString, err)
		}
	}

	if token == nil {
		return nil, fmt.Errorf("not found token in %s:", signedString)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("not found claims in %s", signedString)
	}
	userID, ok := claims[userKey].(string)
	if !ok {
		return nil, fmt.Errorf("not found %s in %s", userKey, signedString)
	}

	return &Auth{
		UserID: userID,
	}, nil
}

func handleRequests() {
	http.Handle("/", isAuthorized(homePage))
	log.Fatal(http.ListenAndServe(":9000", nil))
}

func main() {
	fmt.Println("My simple server")
	handleRequests()
}
