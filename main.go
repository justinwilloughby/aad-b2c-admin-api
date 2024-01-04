package main

import (
	"context"
	"net/http"
	"os"

	azidentity "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/gin-gonic/gin"
	msgraphsdk "github.com/microsoftgraph/msgraph-beta-sdk-go"
	graphmodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
)

type user struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	UserPrincipalName string `json:"userPrincipalName"`
}

func getGraphClient() *msgraphsdk.GraphServiceClient {
	tenantId := os.Getenv("AZURE_TENANT_ID")
	clientId := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")

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
	client := getGraphClient()

	users, _ := client.Users().Get(context.Background(), nil)

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

	client := getGraphClient()

	u, _ := client.Users().ByUserId(id).Get(context.Background(), nil)

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

	client := getGraphClient()

	var displayName string = "John Doe"

	requestBody := graphmodels.NewUser()
	requestBody.SetDisplayName(&displayName)

	_, err := client.Users().ByUserId(id).Patch(context.Background(), requestBody, nil)

	if err != nil {
		c.Header("Content-Type", "application/json")
		c.IndentedJSON(http.StatusInternalServerError, err)
	}

	c.IndentedJSON(http.StatusNoContent, nil)
}

func createUser(c *gin.Context) {
	client := getGraphClient()

	requestBody := graphmodels.NewUser()
	accountEnabled := true
	requestBody.SetAccountEnabled(&accountEnabled)
	displayName := "Adele Vance"
	requestBody.SetDisplayName(&displayName)
	mailNickname := "AdeleV"
	requestBody.SetMailNickname(&mailNickname)
	userPrincipalName := "AdeleV@contosowilloughbyb2c.onmicrosoft.com"
	requestBody.SetUserPrincipalName(&userPrincipalName)
	passwordProfile := graphmodels.NewPasswordProfile()
	forceChangePasswordNextSignIn := true
	passwordProfile.SetForceChangePasswordNextSignIn(&forceChangePasswordNextSignIn)
	password := "xWwvJ]6NMw+bWH-d"
	passwordProfile.SetPassword(&password)
	requestBody.SetPasswordProfile(passwordProfile)

	u, err := client.Users().Post(context.Background(), requestBody, nil)

	if err != nil {
		c.Header("Content-Type", "application/json")
		c.IndentedJSON(http.StatusInternalServerError, err)
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

	client := getGraphClient()

	error := client.Users().ByUserId(id).Delete(context.Background(), nil)

	if error != nil {
		c.Header("Content-Type", "application/json")
		c.IndentedJSON(http.StatusInternalServerError, error)
	}

	c.IndentedJSON(http.StatusNoContent, nil)
}

func main() {
	router := gin.Default()
	router.GET("/users", getUsers)
	router.GET("/users/:id", getUser)
	router.PATCH("/users/:id", updateUser)
	router.POST("/users", createUser)
	router.DELETE("/users/:id", deleteUser)
	router.Run(":8080")
}
