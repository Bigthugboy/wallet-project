package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/Bigthugboy/wallet-project/config"
	"github.com/Bigthugboy/wallet-project/internals"
	"github.com/Bigthugboy/wallet-project/internals/db/query"
	"github.com/Bigthugboy/wallet-project/internals/db/repo"
	"github.com/Bigthugboy/wallet-project/internals/security/keyclock"
	"github.com/anjolabassey/Rave-go/rave"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
)

type Wallet struct {
	App      *config.AppTools
	DB       repo.DBStore
	Keycloak *keyclock.Keycloak
}

func NewWallet(app *config.AppTools, db *gorm.DB) internals.Service {
	return &Wallet{
		App:      app,
		DB:       query.NewWalletDB(app, db),
		Keycloak: keyclock.NewKeycloak(),
	}
}

var secretKey = "FLWSECK_TEST-7c8c2dcff4d2a9cb96fe3a34812e1e90-X"

var card = rave.Card{
	Rave: rave.Rave{
		Live:      false,
		PublicKey: "FLWPUBK_TEST-727132610f7bb0781b0343b0b0de55e7-X",
		SecretKey: secretKey,
	},
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
		baseCurrency := c.Param("base")
		targetCurrency := c.Param("target")
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
			if err == gorm.ErrRecordNotFound {
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
		var payload internals.KLoginPayload
		if err := c.BindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Bad request"})
			log.Println("Error decoding payload:", err)
			return
		}

		_, _, err := w.DB.SearchUserByEmail(payload.Username)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unregistered user"})
			log.Println("user not registered:", payload.Username)
			return
		}
		log.Println("------------------>  ", payload)
		loginRes, err := w.Keycloak.Login(&payload)
		log.Println("------------------>  ", payload)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate JWT tokens"})
			log.Println("error generating JWT tokens:", err)
			return
		}

		response := map[string]string{
			"access_token":  loginRes.AccessToken,
			"refresh_token": loginRes.RefreshToken,
			"token_type":    loginRes.TokenType,
			"session_state": loginRes.SessionState,
			"scope":         loginRes.Scope,
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

// RegisterHandler implements internals.Service.
func (w *Wallet) RegisterHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var user internals.User
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Bad request"})
			log.Println("Error decoding form:", err)
			return
		}
		user.Password, _ = Encrypt(user.Password)
		if err := w.App.Validate.Struct(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Bad request"})
			log.Println("Validation error:", err)
			return
		}
		if err := w.DB.CreateWallet(&user); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			log.Println("Error creating wallet for user:", err)
			return
		}
		_, err := w.DB.InsertUser(user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			log.Println("Error adding user to database:", err)
			return
		}
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
			PublicKey: secretKey,
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
