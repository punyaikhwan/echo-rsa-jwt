package echo_rsa_jwt

import (
	"io/ioutil"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

func GenerateJWT(privateKeyPath string, claims map[string]interface{}) (tokenStr string, err error) {
	signKeyStr, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		log.Fatalf("%s", err.Error())
	}
	signKey, _ := jwt.ParseRSAPrivateKeyFromPEM(signKeyStr)

	token := jwt.New(jwt.GetSigningMethod("RS256"))

	// Set claims
	tclaims := token.Claims.(jwt.MapClaims)
	for k, v := range claims {
		tclaims[k] = v
	}
	tclaims["exp"] = time.Now().Add(time.Minute * 5).Unix()
	// Generate encoded token and send it as response.
	t, err := token.SignedString(signKey)
	return t, err
}

func DecodeJWT(token *jwt.Token) (claims jwt.MapClaims) {
	return token.Claims.(jwt.MapClaims)
}

func JWTEchoRSA(publicKeyPath string) echo.MiddlewareFunc {
	verifyKeyStr, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		log.Fatalf("%s", err.Error())
	}
	verifyKey, _ := jwt.ParseRSAPublicKeyFromPEM(verifyKeyStr)
	return middleware.JWTWithConfig(middleware.JWTConfig{
		SigningKey:    verifyKey,
		SigningMethod: "RS256",
		AuthScheme:    "Bearer",
	})
}
