package main

import (
	"fmt"
	"net/http"
	"sample/domain"
	"sample/tokenutil"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

const Secret = "cmm,:]%e&say=}"

var expiry = 2

var Users = map[string]string{
	"username": "testuser",
	"password": "password",
	"phone":    "1237484924",
	"id":       "1999",
}

var user struct {
	Username string `json:"username"`
	Password string `json:"password"`
	ID       string `json:"id"`
}

type Env struct {
	AccessTokenExpiryHour  int
	RefreshTokenExpiryHour int
	AccessTokenSecret      string
	RefreshTokenSecret     string
}

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
		return
	}
	router := gin.Default()
	router.POST("/login", loginHandler)
	// Apply authentication middleware to protected routes
	protected := router.Group("/protected")
	{
		protected.GET("/profile", profileHandler)
	}

	router.Run(":8080")

}

func loginHandler(c *gin.Context) {

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}
	fmt.Println(user.Username)
	fmt.Println(user.Password)
	// key := user.Username
	storeuser, exists := Users["username"] //users["testuser"]
	if !exists || storeuser != user.Username {

		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid user"})
		return
	}
	storepassword, exists := Users["password"]
	if !exists || storepassword != user.Password {

		c.JSON(http.StatusUnauthorized, gin.H{"message": "User is not authorized to login"})
		return
	}

	accessToken, err := tokenutil.CreateAccessToken(&domain.User{}, Secret, expiry)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User logged in successfully", "access_token": accessToken})
}

func profileHandler(c *gin.Context) {

	authheader := c.Request.Header.Get("Authorization")
	authToken := strings.Split(authheader, " ")[1]

	_, err := tokenutil.IsAuthorized(authToken, Secret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token is invalid", "message": "not authorized"})
		return
	}
	fmt.Println("User authenticated using secret")

	c.JSON(http.StatusOK, gin.H{
		"grant_type": "authorization via secret",
		"message":    "Welcome to your profile",
		"name":       Users["username"],
		"password":   Users["password"],
		"phone":      Users["phone"],
	})
}
