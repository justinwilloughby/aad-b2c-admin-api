package main

import (
	"bufio"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"

	azidentity "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	msgraphsdk "github.com/microsoftgraph/msgraph-beta-sdk-go"
	graphmodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
)

type user struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	UserPrincipalName string `json:"userPrincipalName"`
}

func getGraphClient(tenantId string, clientId string, clientSecret string) *msgraphsdk.GraphServiceClient {
	cred, _ := azidentity.NewClientSecretCredential(
		tenantId,
		clientId,
		clientSecret,
		nil,
	)

	client, _ := msgraphsdk.NewGraphServiceClientWithCredentials(cred, []string{"https://graph.microsoft.com/.default"})

	return client
}

func getUsers(c *gin.Context) {
	client, exists := c.Get("graphClient")

	if !exists {
		c.AbortWithStatusJSON(http.StatusInternalServerError, "Graph client not found")
		return
	}

	graphClient := client.(*msgraphsdk.GraphServiceClient)

	users, _ := graphClient.Users().Get(context.Background(), nil)

	var usersList []user

	for _, u := range users.GetValue() {
		usersList = append(usersList, user{
			ID:                *u.GetId(),
			DisplayName:       *u.GetDisplayName(),
			UserPrincipalName: *u.GetUserPrincipalName(),
		})
	}

	c.Header("Content-Type", "application/json")
	c.IndentedJSON(http.StatusOK, usersList)
}

func getUser(c *gin.Context) {
	id := c.Param("id")

	client, exists := c.Get("graphClient")

	if !exists {
		c.Header("Content-Type", "application/json")
		c.IndentedJSON(http.StatusInternalServerError, "Graph client not found")
	}

	graphClient := client.(*msgraphsdk.GraphServiceClient)

	u, _ := graphClient.Users().ByUserId(id).Get(context.Background(), nil)

	user := user{
		ID:                *u.GetId(),
		DisplayName:       *u.GetDisplayName(),
		UserPrincipalName: *u.GetUserPrincipalName(),
	}

	c.Header("Content-Type", "application/json")
	c.IndentedJSON(http.StatusOK, user)
}

func updateUser(c *gin.Context) {
	id := c.Param("id")

	client, exists := c.Get("graphClient")

	if !exists {
		c.AbortWithStatusJSON(http.StatusInternalServerError, "Graph client not found")
		return
	}

	graphClient := client.(*msgraphsdk.GraphServiceClient)

	var displayName string = "John Doe"

	requestBody := graphmodels.NewUser()
	requestBody.SetDisplayName(&displayName)

	_, err := graphClient.Users().ByUserId(id).Patch(context.Background(), requestBody, nil)

	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, err)
		return
	}

	c.IndentedJSON(http.StatusNoContent, nil)
}

type PasswordProfile struct {
	Password                      string `json:"password"`
	ForceChangePasswordNextSignIn bool   `json:"forceChangePasswordNextSignIn"`
}

type UserRequest struct {
	AccountEnabled    bool            `json:"accountEnabled"`
	DisplayName       string          `json:"displayName"`
	MailNickname      string          `json:"mailNickname"`
	UserPrincipalName string          `json:"userPrincipalName"`
	PasswordProfile   PasswordProfile `json:"passwordProfile"`
}

func createUser(c *gin.Context) {
	client, exists := c.Get("graphClient")

	if !exists {
		c.AbortWithStatusJSON(http.StatusInternalServerError, "Graph client not found")
		return
	}

	var userRequest UserRequest

	err := c.BindJSON(&userRequest)

	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, err)
		return
	}

	graphClient := client.(*msgraphsdk.GraphServiceClient)

	requestBody := graphmodels.NewUser()
	accountEnabled := userRequest.AccountEnabled
	requestBody.SetAccountEnabled(&accountEnabled)
	displayName := userRequest.DisplayName
	requestBody.SetDisplayName(&displayName)
	mailNickname := userRequest.MailNickname
	requestBody.SetMailNickname(&mailNickname)
	userPrincipalName := userRequest.UserPrincipalName
	requestBody.SetUserPrincipalName(&userPrincipalName)
	passwordProfile := graphmodels.NewPasswordProfile()
	forceChangePasswordNextSignIn := userRequest.PasswordProfile.ForceChangePasswordNextSignIn
	passwordProfile.SetForceChangePasswordNextSignIn(&forceChangePasswordNextSignIn)
	password := userRequest.PasswordProfile.Password
	passwordProfile.SetPassword(&password)
	requestBody.SetPasswordProfile(passwordProfile)

	u, err := graphClient.Users().Post(context.Background(), requestBody, nil)

	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, err)
		return
	}

	user := user{
		ID:                *u.GetId(),
		DisplayName:       *u.GetDisplayName(),
		UserPrincipalName: *u.GetUserPrincipalName(),
	}

	c.Header("Content-Type", "application/json")
	c.IndentedJSON(http.StatusOK, user)
}

func deleteUser(c *gin.Context) {
	id := c.Param("id")

	client, exists := c.Get("graphClient")

	if !exists {
		c.AbortWithStatusJSON(http.StatusInternalServerError, "Graph client not found")
		return
	}

	graphClient := client.(*msgraphsdk.GraphServiceClient)

	err := graphClient.Users().ByUserId(id).Delete(context.Background(), nil)

	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, err)
		return
	}

	c.IndentedJSON(http.StatusNoContent, nil)
}

func getConfig() (string, string, string) {
	var isLocal string = "false"

	if len(os.Args) > 1 {
		isLocal = os.Args[1]
	}

	var file *os.File
	var err error

	if isLocal == "true" {
		file, err = os.Open("./secrets/sample-config.txt")
	} else {
		file, err = os.Open("/app/secrets/config.txt")
	}

	if err != nil {
		fmt.Println(err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	var tenantId string
	var clientId string
	var clientSecret string

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "AZURE_TENANT_ID") {
			tenantId = strings.Split(line, "=")[1]
		} else if strings.Contains(line, "AZURE_CLIENT_ID") {
			clientId = strings.Split(line, "=")[1]
		} else if strings.Contains(line, "AZURE_CLIENT_SECRET") {
			clientSecret = strings.Split(line, "=")[1]
		}
	}

	return tenantId, clientId, clientSecret
}

func GraphClientMiddleware(tenantId string, clientId string, clientSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		graphClient := getGraphClient(tenantId, clientId, clientSecret)
		c.Set("graphClient", graphClient)
		c.Next()
	}
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func getKey(jwksUrl string) (string, string) {
	resp, err := http.Get(jwksUrl)
	if err != nil {
		fmt.Println(err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		fmt.Println(err)
	}

	type Key struct {
		N string `json:"n"`
		E string `json:"e"`
	}

	type Keys struct {
		Key []Key `json:"keys"`
	}

	var Jwks Keys

	err = json.Unmarshal(body, &Jwks)

	if err != nil {
		fmt.Println(err)
	}

	return Jwks.Key[0].N, Jwks.Key[0].E
}

func validateAccessToken(accessToken string) (bool, error) {
	audience := "e3508248-371c-4b76-bdf1-067eaf47a556"
	issuer := "https://contosowilloughbyb2c.b2clogin.com/926e4587-9275-41b9-a9b2-f4a41354f511/v2.0/"
	scope := "Users.ReadWrite"

	jwksUrl := "https://contosowilloughbyb2c.b2clogin.com/contosowilloughbyb2c.onmicrosoft.com/b2c_1_signuporsignin/discovery/keys"

	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		n, e := getKey(jwksUrl)

		nDecoded, _ := base64.RawURLEncoding.DecodeString(n)
		eDecoded, _ := base64.RawURLEncoding.DecodeString(e)

		nBigInt := new(big.Int)
		eBigInt := new(big.Int)

		nBigInt.SetBytes(nDecoded)
		eBigInt.SetBytes(eDecoded)

		publicKey := &rsa.PublicKey{
			N: nBigInt,
			E: int(eBigInt.Uint64()),
		}

		return publicKey, nil
	},
		jwt.WithAudience(audience),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt())

	if err != nil {
		return false, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if !strings.Contains(claims["scp"].(string), scope) {
			return false, nil
		}
	} else {
		return false, err
	}

	return true, nil
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")

		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, "Missing authorization header")
			return
		}

		accessToken := strings.Split(authHeader, " ")[1]

		isValid, err := validateAccessToken(accessToken)

		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, err)
			return
		}

		if !isValid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, "Invalid access token")
			return
		}

		c.Next()
	}
}

func main() {

	tenantId, clientId, clientSecret := getConfig()

	router := gin.Default()

	router.Use(corsMiddleware())

	router.Use(authMiddleware())

	router.Use(GraphClientMiddleware(tenantId, clientId, clientSecret))

	router.GET("/users", getUsers)
	router.GET("/users/:id", getUser)
	router.PATCH("/users/:id", updateUser)
	router.POST("/users", createUser)
	router.DELETE("/users/:id", deleteUser)

	router.Run(":8080")
}
