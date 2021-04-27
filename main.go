package echo_rsa_jwt

import (
	"io/ioutil"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type GenerateJWTInput struct {
	PrivateKeyPath string
	Claims         map[string]interface{}
	MinuteToExpire int
}

func GenerateJWT(input GenerateJWTInput) (tokenStr string, err error) {
	signKeyStr, err := ioutil.ReadFile(input.PrivateKeyPath)
	if err != nil {
		log.Fatalf("%s", err.Error())
	}
	signKey, _ := jwt.ParseRSAPrivateKeyFromPEM(signKeyStr)

	token := jwt.New(jwt.GetSigningMethod("RS256"))

	// Set claims
	tclaims := token.Claims.(jwt.MapClaims)
	for k, v := range input.Claims {
		tclaims[k] = v
	}
	tclaims["exp"] = time.Now().Add(time.Minute * time.Duration(input.MinuteToExpire)).Unix()
	// Generate encoded token and send it as response.
	t, err := token.SignedString(signKey)
	return t, err
}

func DecodeJWT(token *jwt.Token) (claims jwt.MapClaims) {
	return token.Claims.(jwt.MapClaims)
}
