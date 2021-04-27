package middleware

import (
	"io/ioutil"
	"log"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

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
