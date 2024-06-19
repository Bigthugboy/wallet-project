package keyclock

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/Bigthugboy/wallet-project/internals"
	"github.com/golang-jwt/jwt/v5"
)

var secretKey = []byte("404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970")

type keycloak struct {
	AuthKeyMutex sync.RWMutex
	BearerToken  string
}

func GenerateToken(payload *internals.GenerateRequest) (string, error) {
	form := url.Values{
		"client_id":     {payload.ClientId},
		"client_secret": {payload.ClientSecret},
		"grant_type":    {payload.GrantType},
		"username":      {payload.Username},
		"password":      {payload.Password},
	}
	encodedData := form.Encode()
	req, err := http.NewRequest("POST", "http://localhost:8080/realms/test/protocol/openid-connect/token", strings.NewReader(encodedData))
	if err != nil {
		log.Println("Error creating request: ", err)
		return "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error performing request: ", err)
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Println("Non-OK HTTP status: ", resp.StatusCode)
		return "", errors.New("something went wrong while connecting to Keycloak")
	}

	var tokenResponse internals.TokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
	if err != nil {
		log.Println("Error decoding response: ", err)
		return "", err
	}

	k := keycloak{}
	k.AuthKeyMutex.Lock()
	k.BearerToken = tokenResponse.AccessToken
	k.AuthKeyMutex.Unlock()

	return tokenResponse.AccessToken, nil
}

func Login(payload *internals.KLoginPayload) (*internals.KLoginRes, error) {

	formData := url.Values{
		"client_id":     {payload.ClientID},
		"client_secret": {payload.ClientSecret},
		"grant_type":    {payload.GrantType},
		"username":      {payload.Username},
		"password":      {payload.Password},
	}
	encodedFormData := formData.Encode()

	req, err := http.NewRequest("POST", "http://localhost:8080/realms/test/protocol/openid-connect/token", strings.NewReader(encodedFormData))
	if err != nil {
		log.Println("Error creating request: ", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error performing request: ", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Println("Non-OK HTTP status: ", resp.StatusCode)
		return nil, errors.New("something went wrong while connecting to Keycloak")
	}

	kloginresp := &internals.KLoginRes{}

	err = json.NewDecoder(resp.Body).Decode(kloginresp)
	if err != nil {
		log.Println("Error decoding response: ", err)
		return nil, err
	}

	return kloginresp, nil

}

func ValidateToken(token string) (bool, error) {
	keycloakPublicKey, err := fetchKeycloakPublicKey()
	if err != nil {
		return false, err
	}

	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Ensure the token method conforms to "RS256"
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Parse the public key
		publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(keycloakPublicKey))
		if err != nil {
			return nil, err
		}

		return publicKey, nil
	})
	if err != nil {
		return false, err
	}

	return parsedToken.Valid, nil
}
func fetchKeycloakPublicKey() (string, error) {
	resp, err := http.Get("http://localhost:8080/realms/test/protocol/openid-connect/certs")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("failed to fetch public key from Keycloak")
	}

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// You need to parse the JSON response to extract the public key
	// For simplicity, assuming the public key is available as a single string
	// In practice, you would parse the JWK and convert it to PEM format
	var keycloakPublicKey string

	// Implement JSON parsing to extract the public key from the response
	// For example, use a library like "encoding/json" to parse the response

	return keycloakPublicKey, nil
}
