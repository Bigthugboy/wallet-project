package keyclock

import (
	"errors"
	"log"

	"github.com/Bigthugboy/wallet-project/internals"
	"github.com/Nerzal/gocloak"
)

type Keycloak struct {
	ClientID     string
	ClientSecret string
	Realm        string
	goCloak      gocloak.GoCloak
}

func NewKeycloak() *Keycloak {
	return &Keycloak{
		goCloak:      gocloak.NewClient("http://localhost:8080"),
		ClientID:     "wallet-test",
		ClientSecret: "ZARfeL8Krkk6mAZEXWkrZuzTE6hUeB4",
		Realm:        "Test",
	}
}

func (k *Keycloak) Login(payload *internals.KLoginPayload) (*internals.KLoginRes, error) {
	if payload == nil || payload.Username == "" || payload.Password == "" {
		log.Println(payload)
		return nil, errors.New("invalid login payload")
	}

	token, err := k.goCloak.Login(k.ClientID, k.ClientSecret, k.Realm, payload.Username, payload.Password)
	if err != nil {
		log.Printf("Login failed for user %s: %v", payload.Username, err)
		return nil, err
	}

	loginRes := &internals.KLoginRes{
		AccessToken:      token.AccessToken,
		ExpiresIn:        token.ExpiresIn,
		RefreshExpiresIn: token.RefreshExpiresIn,
		RefreshToken:     token.RefreshToken,
		TokenType:        token.TokenType,
		NotBeforePolicy:  token.NotBeforePolicy,
		SessionState:     token.SessionState,
		Scope:            token.Scope,
	}

	log.Printf("User %s logged in successfully", payload.Username)
	return loginRes, nil
}

// const (
// 	KeycloakBaseURL      = "http://localhost:8080"
// 	Realm                = "Test"
// 	KeycloakClientID     = "Wallet-test"
// 	KeycloakClientSecret = "kYZuoM13FjxSmIjRcSMf8Ujz9UHC7NC6"
// )

// type KLoginPayload struct {
// 	ClientID     string
// 	ClientSecret string
// 	Username     string
// 	Password     string
// }

// type KLoginRes struct {
// 	AccessToken string
// 	ExpiresIn   int
// }

// type UserInfo struct {
// 	Username string
// }

// func main() {
// 	client := &http.Client{}

// 	// Test login
// 	payload := &KLoginPayload{
// 		ClientID:     KeycloakClientID,
// 		ClientSecret: KeycloakClientSecret,
// 		Username:     "test-wallet",
// 		Password:     "Labete",
// 	}
// 	issueTime := time.Now()
// 	loginRes, err := login(client, payload)
// 	if err != nil {
// 		fmt.Printf("Login failed: %v\n", err)
// 		return
// 	}

// 	fmt.Printf("Login successful: %v\n", loginRes.AccessToken)

// 	// Check if the token is still active
// 	if time.Since(issueTime).Seconds() < float64(loginRes.ExpiresIn) {
// 		// The token is still active
// 		userInfo, err := extractUserInfo(client, loginRes.AccessToken)
// 		if err != nil {
// 			fmt.Printf("Extract user info failed: %v\n", err)
// 			return
// 		}
// 		fmt.Printf("User info: %+v\n", userInfo)
// 	} else {
// 		// The token has expired
// 		fmt.Println("The token has expired. Please login again.")
// 	}
// }

// func login(client *http.Client, payload *KLoginPayload) (*KLoginRes, error) {
// 	formData := url.Values{
// 		"client_id":     {payload.ClientID},
// 		"client_secret": {payload.ClientSecret},
// 		"grant_type":    {"password"},
// 		"username":      {payload.Username},
// 		"password":      {payload.Password},
// 		"scope":         {"openid profile email"},
// 	}
// 	encodedFormData := formData.Encode()

// 	loginURL := KeycloakBaseURL + "/realms/" + Realm + "/protocol/openid-connect/token"
// 	req, err := http.NewRequest("POST", loginURL, strings.NewReader(encodedFormData))
// 	if err != nil {
// 		return nil, err
// 	}
// 	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

// 	resp, err := client.Do(req)
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer resp.Body.Close()

// 	if resp.StatusCode != http.StatusOK {
// 		body, _ := io.ReadAll(resp.Body)
// 		return nil, fmt.Errorf("failed to login user, status code: %s, body: %s", resp.Status, string(body))
// 	}

// 	loginRes := &KLoginRes{}
// 	err = json.NewDecoder(resp.Body).Decode(loginRes)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return loginRes, nil
// }

// func extractUserInfo(client *http.Client, accessToken string) (*UserInfo, error) {
// 	userInfoURL := KeycloakBaseURL + "/realms/" + Realm + "/protocol/openid-connect/userinfo"
// 	req, err := http.NewRequest("GET", userInfoURL, nil)
// 	if err != nil {
// 		return nil, err
// 	}
// 	req.Header.Set("Authorization", "Bearer "+accessToken)

// 	resp, err := client.Do(req)
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer resp.Body.Close()

// 	if resp.StatusCode != http.StatusOK {
// 		body, _ := io.ReadAll(resp.Body)
// 		return nil, fmt.Errorf("failed to extract user info, status code: %s, body: %s", resp.Status, string(body))
// 	}

// 	userInfo := &UserInfo{}
// 	err = json.NewDecoder(resp.Body).Decode(userInfo)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return userInfo, nil
// }
