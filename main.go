package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	googleOauthConfig *oauth2.Config
)

func init() {
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:3000/auth/google/callback",
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}
}

func main() {
	app := fiber.New()

	app.Get("/auth/google", handleGoogleLogin)
	app.Get("/auth/google/callback", handleGoogleCallback)
	app.Post("/auth/google/tokenauth", handleGoogleTokenAuth)
	log.Fatal(app.Listen(":3000"))
}

func handleGoogleLogin(c *fiber.Ctx) error {
	url := googleOauthConfig.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	return c.Redirect(url)
}

func handleGoogleCallback(c *fiber.Ctx) error {
	code := c.Query("code")
	if code == "" {
		return c.Status(http.StatusBadRequest).SendString("Code not found")
	}

	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return c.Status(http.StatusInternalServerError).SendString("Failed to exchange token: " + err.Error())
	}
	fmt.Printf("Token: %v", token.AccessToken)
	client := googleOauthConfig.Client(context.Background(), token)
	response, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return c.Status(http.StatusInternalServerError).SendString("Failed to get user info: " + err.Error())
	}
	defer response.Body.Close()

	var userInfo map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&userInfo); err != nil {
		return c.Status(http.StatusInternalServerError).SendString("Failed to parse user info: " + err.Error())
	}

	return c.JSON(userInfo)
}

type GoogleTokenAuthRequest struct {
	Token string `json:"access_token"`
}

type UserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func handleGoogleTokenAuth(c *fiber.Ctx) error {
	tokenReq := GoogleTokenAuthRequest{}
	if err := c.BodyParser(&tokenReq); err != nil {
		return c.Status(http.StatusBadRequest).SendString("Invalid request")
	}
	if tokenReq.Token == "" {
		return c.Status(http.StatusBadRequest).SendString("Token is not found")
	}

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.SetRequestURI("https://www.googleapis.com/oauth2/v2/userinfo")
	req.Header.SetMethod(fasthttp.MethodGet)
	req.Header.Set("Authorization", "Bearer "+tokenReq.Token)

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	err := fasthttp.Do(req, resp)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to get user info: " + err.Error())
	}

	var userInfo UserInfo
	if err := json.Unmarshal(resp.Body(), &userInfo); err != nil {
		return c.Status(http.StatusInternalServerError).SendString("Failed to parse user info: " + err.Error())
	}
	return c.JSON(userInfo)
}
