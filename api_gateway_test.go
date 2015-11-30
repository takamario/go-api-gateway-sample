package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func parseBody(body *bytes.Buffer) map[string]interface{} {
	var bodyBytes []byte
	bodyBytes, _ = ioutil.ReadAll(body)
	resBody := make(map[string]interface{})
	_ = json.Unmarshal(bodyBytes, &resBody)
	return resBody
}

func createToken() string {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims["exp"] = time.Now().Add(time.Minute * 30).Unix()
	key, _ := ioutil.ReadFile("keys/sample_key")
	parsedKey, _ := jwt.ParseRSAPrivateKeyFromPEM(key)
	tokenString, _ := token.SignedString(parsedKey)
	return tokenString
}

func createRequest(r http.Handler, method, path string) (*closeNotifyingRecorder, *http.Request) {
	req, _ := http.NewRequest(method, path, nil)
	res := newCloseNotifyingRecorder()
	return res, req
}

// magic!
type closeNotifyingRecorder struct {
	*httptest.ResponseRecorder
	closed chan bool
}

func newCloseNotifyingRecorder() *closeNotifyingRecorder {
	return &closeNotifyingRecorder{
		httptest.NewRecorder(),
		make(chan bool, 1),
	}
}

func (c *closeNotifyingRecorder) close() {
	c.closed <- true
}

func (c *closeNotifyingRecorder) CloseNotify() <-chan bool {
	return c.closed
}

func TestNotFound(t *testing.T) {
	assert := assert.New(t)

	router := gin.New()
	router.NoRoute(NotFoundHandler)

	w, r := createRequest(router, "GET", "/api/v1/not_found")
	router.ServeHTTP(w, r)
	resBody := parseBody(w.Body)

	assert.Equal(http.StatusNotFound, w.Code, "should be equal")
	assert.Equal("Not Found", resBody["error"], "should be equal")
}

func TestHealthCheck(t *testing.T) {
	assert := assert.New(t)

	router := gin.New()
	router.GET("/api/v1/healthcheck", ReverseProxyHandler)

	w, r := createRequest(router, "GET", "/api/v1/healthcheck")
	router.ServeHTTP(w, r)
	resBody := parseBody(w.Body)

	assert.Equal(http.StatusOK, w.Code, "should be equal")
	assert.Equal("ok", resBody["status"], "should be equal")
}

func TestUserGetWithoutToken(t *testing.T) {
	assert := assert.New(t)

	router := gin.New()
	authorized := router.Group("/", CheckJWTHandler)
	authorized.GET("/api/v1/users/:userId", ReverseProxyHandler)

	w, r := createRequest(router, "GET", "/api/v1/users/1")
	router.ServeHTTP(w, r)
	resBody := parseBody(w.Body)

	assert.Equal(http.StatusUnauthorized, w.Code, "should be equal")
	assert.Equal("Unauthorized", resBody["error"], "should be equal")
}

func TestUserGetWithInvalidToken(t *testing.T) {
	assert := assert.New(t)

	router := gin.New()
	authorized := router.Group("/", CheckJWTHandler)
	authorized.GET("/api/v1/users/:userId", ReverseProxyHandler)

	w, r := createRequest(router, "GET", "/api/v1/users/1")
	r.Header.Set("Authorization", "Bearer thisisinvalidtoken")
	router.ServeHTTP(w, r)
	resBody := parseBody(w.Body)

	assert.Equal(http.StatusUnauthorized, w.Code, "should be equal")
	assert.Equal("Unauthorized", resBody["error"], "should be equal")
}

func TestUserGetWithValidToken(t *testing.T) {
	assert := assert.New(t)

	router := gin.New()
	authorized := router.Group("/", CheckJWTHandler)
	authorized.GET("/api/v1/users/:userId", ReverseProxyHandler)

	w, r := createRequest(router, "GET", "/api/v1/users/1")
	tokenString := createToken()
	r.Header.Set("Authorization", "Bearer "+tokenString)
	router.ServeHTTP(w, r)
	resBody := parseBody(w.Body)

	assert.Equal(http.StatusOK, w.Code, "should be equal")
	assert.Equal(1, int(resBody["id"].(float64)), "should be equal")
	assert.Equal("John Doe", resBody["name"], "should be equal")
}
