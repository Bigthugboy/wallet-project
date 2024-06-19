package controller

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Bigthugboy/wallet-project/config"
	"github.com/Bigthugboy/wallet-project/internals"
	"github.com/Bigthugboy/wallet-project/internals/db/query"
	"github.com/Bigthugboy/wallet-project/internals/db/repo"
	"github.com/Bigthugboy/wallet-project/internals/security/keyclock"
	"github.com/anjolabassey/Rave-go/rave"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
)

type Wallet struct {
	App          *config.AppTools
	DB           repo.DBStore
	AuthKeyMutex sync.RWMutex
	BearerToken  string
}

var card = rave.Card{
	Rave: rave.Rave{
		Live:      false,
		PublicKey: "FLWPUBK_TEST-727132610f7bb0781b0343b0b0de55e7-X",
		SecretKey: "FLWSECK_TEST-7c8c2dcff4d2a9cb96fe3a34812e1e90-X",
	},
}

func NewWallet(app *config.AppTools, db *gorm.DB) internals.Service {
	return &Wallet{
		App: app,
		DB:  query.NewWalletDB(app, db),
	}
}

func Encrypt(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("no input value")
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to generate encrypted password: %v", err)
	}
	return string(hashedPassword), nil
}

func (w *Wallet) GenerateHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var payload internals.GenerateCliReq
		if err := c.BindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Bad request"})
			log.Println("Error decoding payload:", err)
			return
		}
		log.Println("Received login payload:", payload)

		kLogin := internals.GenerateRequest{
			ClientId:     "supper-client",
			ClientSecret: "sbzfcpBSZ1RgXnOutmVI7gyvz4gyLnvL",
			GrantType:    "client_credentials",
			Username:     "admin",
			Password:     "admin",
		}

		token, err := keyclock.GenerateToken(&kLogin)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate JWT tokens"})
			log.Println("Error generating JWT tokens:", err)
			return
		}
		var response internals.TokenResponse
		response.AccessToken = token

		w.AuthKeyMutex.Lock()
		w.BearerToken = token
		w.AuthKeyMutex.Unlock()

		c.JSON(http.StatusOK, response)
	}
}
func (w *Wallet) CheckBalance() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Print("check if endpoint was hit")
		userID := c.Param("userID")
		walletID := c.Param("walletID")
		balance, err := w.DB.GetWalletBalance(userID, walletID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Bad request"})

			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error getting wallet balance"})
			}
			log.Printf("Failed to get wallet balance: %v", err)
			return
		}
		log.Printf("log balance %v", balance)
		c.JSON(http.StatusOK, gin.H{"balance": fmt.Sprintf("Your balance is: %.2f", balance)})
	}
}

// GetExchangeRate implements internals.Service.
func (w *Wallet) GetExchangeRate() gin.HandlerFunc {
	return func(c *gin.Context) {
		baseCurrency := c.Param("baseCurrency")
		targetCurrency := c.Param("targetCurrency")
		apiURL := fmt.Sprintf("https://api.exchangeratesapi.io/latest?base=%s&symbols=%s", baseCurrency, targetCurrency)
		resp, err := http.Get(apiURL)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch exchange rates"})
			log.Println("Error fetching exchange rates:", err)
			return
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read response body"})
			log.Println("Error reading response body:", err)
			return
		}
		// Parse the JSON response
		var data map[string]map[string]float64
		if err := json.Unmarshal(body, &data); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse JSON response"})
			log.Println("Error parsing JSON response:", err)
			return
		}

		exchangeRate := data["rates"][targetCurrency]

		c.JSON(http.StatusOK, exchangeRate)
	}

}

// GetTransactionWithID implements internals.Service.
func (w *Wallet) GetTransactionWithID() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("userID")
		transactionID := c.Param("transactionID")
		transaction, err := w.DB.GetTransactionWithID(userID, transactionID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "Transaction not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error getting transaction"})
			log.Printf("Failed to get transaction: %v", err)
			return
		}
		response, err := json.Marshal(transaction)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error encoding transaction to JSON"})
			log.Printf("Failed to encode transaction to JSON: %v", err)
			return
		}

		c.JSON(http.StatusOK, string(response))
	}
}

func (w *Wallet) LoginHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var payload internals.LoginUser
		if err := c.BindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Bad request"})
			log.Println("Error decoding payload:", err)
			return
		}
		log.Println("Received login payload:", payload)
		_, _, err := w.DB.SearchUserByEmail(payload.Email)
		if err != nil {
			log.Println("User not registered:", payload.Email)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error! user not found"})
			return
		}

		kLogin := internals.KLoginPayload{
			ClientID:     "supper-client",
			Username:     payload.Email,
			Password:     payload.Password,
			GrantType:    "password",
			ClientSecret: "sbzfcpBSZ1RgXnOutmVI7gyvz4gyLnvL",
		}

		token, err := keyclock.Login(&kLogin)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate JWT tokens"})
			log.Println("Error generating JWT tokens:", err)
			return
		}

		response := map[string]string{
			"access_token":  token.AccessToken,
			"refresh_token": token.RefreshToken,
			"token_type":    token.TokenType,
			"session_state": token.SessionState,
			"scope":         token.Scope,
		}

		c.JSON(http.StatusOK, response)
	}
}

// MakePayment implements internals.Service.
func (w *Wallet) MakePayment() gin.HandlerFunc {
	return func(c *gin.Context) {
		var payload internals.PayLoad
		if err := c.ShouldBindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Bad request"})
			log.Println("Error decoding payload:", err)
			return
		}
		details := rave.CardChargeData{
			Cardno:        payload.CardNo,
			Cvv:           payload.Cvv,
			Expirymonth:   payload.ExpiryMonth,
			Expiryyear:    payload.ExpiryYear,
			Pin:           payload.Pin,
			Amount:        payload.Amount,
			Currency:      "NGN",
			CustomerPhone: payload.Phone,
			Firstname:     payload.FirstName,
			Lastname:      payload.LastName,
			Email:         payload.Email,
			Txref:         payload.TxRef,
			RedirectUrl:   "https://localhost:9090/checkBalance",
		}

		// Charge the card
		err, resp := card.ChargeCard(details)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			log.Println("Error charging card:", err)
			return
		}
		transaction := internals.Wallet{
			UserID:   payload.UserID,
			Balance:  details.Amount,
			Currency: details.Currency,
			Amount:   details.Amount,
			Method:   "Card Payment",
		}
		_, err = w.DB.SavePayment(transaction)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			log.Println("Error saving payment:", err)
			return
		}
		err = w.DB.UpdateWalletBalance(payload.UserID, payload.Amount)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			log.Println("Error updating wallet balance:", err)
			return
		}
		c.JSON(http.StatusOK, resp)
	}
}

func (w *Wallet) RegisterHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var user internals.User
		logrus.Info("Received registration request")

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Bad request"})
			logrus.WithError(err).Error("Error decoding form")
			return
		}

		user.Password, _ = Encrypt(user.Password)
		if err := w.App.Validate.Struct(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Bad request"})
			logrus.WithError(err).Error("Validation error")
			return
		}
		logrus.WithFields(logrus.Fields{
			"username": user.Username,
			"email":    user.Email,
		}).Info("Validated user data")

		kCreatePayload := internals.KCreateUserPayload{
			Username:      user.Username,
			FirstName:     user.FirstName,
			LastName:      user.LastName,
			Email:         user.Email,
			EmailVerified: true,
			Enabled:       true,
			Credentials: []internals.KUserCredential{
				{
					Type:      "password",
					Value:     "password",
					Temporary: false,
				},
			},
			Attributes: map[string]interface{}{
				"attributes_key": "test_value",
			},
		}

		jsonData, err := json.Marshal(kCreatePayload)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating JSON payload"})
			logrus.WithError(err).Error("Error marshaling JSON")
			return
		}

		logrus.WithField("payload", string(jsonData)).Info("Sending create user request to Keycloak")

		req, err := http.NewRequest("POST", "http://localhost:8080/admin/realms/test/users", bytes.NewBuffer(jsonData))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating request"})
			logrus.WithError(err).Error("Error creating request")
			return
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+w.BearerToken)

		logrus.WithField("bearer_token", w.BearerToken).Info("Using Bearer token for Keycloak request")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error performing request"})
			logrus.WithError(err).Error("Error performing request")
			return
		}
		defer resp.Body.Close()

		logrus.WithField("status_code", resp.StatusCode).Info("Received response from Keycloak")

		if resp.StatusCode != http.StatusCreated {
			errorMsg := "Failed to create user in Keycloak"
			if resp.Body != nil {
				errorBody, _ := ioutil.ReadAll(resp.Body)
				errorMsg += ". Response Body: " + string(errorBody)
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": errorMsg})
			logrus.WithField("status_code", resp.StatusCode).Error("Non-OK HTTP status")
			return
		}
		var kCreateResp internals.KCreateRes
		if err := json.NewDecoder(resp.Body).Decode(&kCreateResp); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error decoding response"})
			logrus.WithError(err).Error("Error decoding response")
			return
		}
		logrus.WithFields(logrus.Fields{
			"username": user.Username,
			"email":    user.Email,
		}).Info("User created successfully in Keycloak")

		_, err = w.DB.InsertUser(user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error adding user to database"})
			logrus.WithError(err).Error("Error adding user to database")
			return
		}
		logrus.Info("User registration completed successfully")
		c.JSON(http.StatusOK, gin.H{"message": "Registered Successfully"})
	}
}

// TransactionHistory implements internals.Service.
func (w *Wallet) TransactionHistory() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("userID")
		transactions, err := w.DB.GetAllTransactions(userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error getting transaction from database"})
			log.Printf("Failed to get documents from database: %v", err)
			return
		}
		if len(transactions) == 0 {
			c.JSON(http.StatusOK, gin.H{"message": "You haven't made any transactions yet"})
			log.Println("You haven't made any transactions yet")
			return
		}
		res, err := json.Marshal(transactions)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error encoding transactions to JSON"})
			log.Printf("Failed to encode transactions to JSON: %v", err)
			return
		}
		c.JSON(http.StatusOK, string(res))
	}
}

// validate payment
func (w *Wallet) ValidatePayment() gin.HandlerFunc {
	return func(c *gin.Context) {
		var validatePayload internals.ValidatePayload
		if err := c.ShouldBindJSON(&validatePayload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Bad request"})
			log.Println("Error decoding validation payload:", err)
			return
		}

		payload := rave.CardValidateData{
			Otp:       validatePayload.Otp,
			Reference: validatePayload.Reference,
			PublicKey: card.PublicKey,
		}

		// Validate the card
		err, resp := card.ValidateCard(payload)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			log.Println("Error validating card:", err)
			return
		}
		c.JSON(http.StatusOK, resp)
	}
}
