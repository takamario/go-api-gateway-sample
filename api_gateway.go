package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()

	v1 := router.Group("/api/v1")
	{
		// Without Authorization
		v1.GET("/healthcheck", ReverseProxyHandler)

		// With Authorization
		authorized := v1.Group("/", CheckJWTHandler)
		authorized.GET("/users/:userId", ReverseProxyHandler)
	}

	router.NoRoute(NotFoundHandler)

	router.Run(":3000")
}

func CheckJWTHandler(c *gin.Context) {
	authorizationHeader := c.Request.Header.Get("Authorization")
	if authorizationHeader == "" {
		Unauthorized(c)
		return
	}
	if authorizationHeader[:7] != "Bearer " {
		Unauthorized(c)
		return
	}
	tokenString := authorizationHeader[7:]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return LookupPublicKey()
	})
	if err != nil || !token.Valid {
		Unauthorized(c)
		return
	}
}

func LookupPublicKey() (*rsa.PublicKey, error) {
	key, _ := ioutil.ReadFile("keys/sample_key.pub")
	parsedKey, err := jwt.ParseRSAPublicKeyFromPEM(key)
	return parsedKey, err
}

func ReverseProxyHandler(c *gin.Context) {
	// Dummy backend (Change to your real API)
	backend := RunDummyBackend()
	defer backend.Close()

	remoteUrl, _ := url.Parse(backend.URL)
	proxy := httputil.NewSingleHostReverseProxy(remoteUrl)
	proxy.ServeHTTP(c.Writer, c.Request)
}

func NotFoundHandler(c *gin.Context) {
	c.JSON(http.StatusNotFound, gin.H{
		"error": http.StatusText(http.StatusNotFound),
	})
	c.Abort()
}

func Unauthorized(c *gin.Context) {
	c.JSON(http.StatusUnauthorized, gin.H{
		"error": http.StatusText(http.StatusUnauthorized),
	})
	c.Abort()
}

func RunDummyBackend() *httptest.Server {
	backend := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		var resMap map[string]interface{}
		if req.URL.Path == "/api/v1/users/1" {
			resMap = map[string]interface{}{
				"id":   1,
				"name": "John Doe",
			}
		} else if req.URL.Path == "/api/v1/healthcheck" {
			resMap = map[string]interface{}{
				"status": "ok",
			}
		} else {
			resMap = map[string]interface{}{
				"error": http.StatusText(http.StatusNotFound),
			}
			res.WriteHeader(http.StatusNotFound)
		}
		js, _ := json.Marshal(resMap)
		res.Header().Set("Content-Type", "application/json")
		res.Write(js)
	}))
	return backend
}
