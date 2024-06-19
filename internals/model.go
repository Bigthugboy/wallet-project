package internals

import (
	"github.com/jinzhu/gorm"
)

type User struct {
	gorm.Model
	FirstName   string `json:"firstName"`
	Username    string `json:"username"`
	LastName    string `json:"lastName"`
	Email       string `json:"email" gorm:"unique;not null"`
	Password    string `json:"password" gorm:"not null"`
	PhoneNumber string `json:"phone" gorm:"not null"`
	Wallet      Wallet `json:"wallet"`
}
type UserInfo struct {
	ID       int64
	Email    string
	Password string
}
type KLoginPayload struct {
	ClientID     string
	Username     string
	Password     string
	GrantType    string
	ClientSecret string
	Email        string
	password     string
}

type LoginUser struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type KLoginRes struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not_before_policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}

type Wallet struct {
	gorm.Model
	UserID   int
	Balance  float64 `json:"balance" `
	Currency string  `json:"currency"`
	Method   string  `json:"method"`
	Amount   float64 `json:"amount"`
}

type Transaction struct {
	gorm.Model
	UserID   uint
	WalletID uint
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
}

type PayLoad struct {
	FirstName   string  `json:"first_name" Usage:"required,alpha"`
	LastName    string  `json:"last_name" Usage:"required,alpha"`
	Amount      float64 `json:"amount"`
	TxRef       string  `json:"tx_ref"`
	Email       string  `json:"email"`
	Phone       string  `json:"phone"`
	Currency    string  `json:"currency"`
	CardNo      string  `json:"cardno"`
	Cvv         string  `json:"cvv"`
	Pin         string  `json:"pin"`
	ExpiryMonth string  `json:"expirymonth"`
	ExpiryYear  string  `json:"expiryyear"`
	UserID      int     `json:"userId"`
}
type ValidatePayload struct {
	Reference string `json:"tx_ref"`
	Otp       string `json:"otp"`
	PublicKey string `json:"PBFPubKey"`
}
type KCreateUserPayload struct {
	Username      string                 `json:"username"`
	FirstName     string                 `json:"firstName"`
	LastName      string                 `json:"lastName"`
	Email         string                 `json:"email"`
	Password      string                 `json:"password"`
	EmailVerified bool                   `json:"emailVerified"`
	Enabled       bool                   `json:"enabled"`
	Credentials   []KUserCredential      `json:"credentials"`
	Attributes    map[string]interface{} `json:"attributes"`
}

type KUserCredential struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Temporary bool   `json:"temporary"`
}

type KCreateRes struct {
	Message string `json:"message"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type GenerateRequest struct {
	ClientId     string
	ClientSecret string
	GrantType    string
	Username     string
	Password     string
}
type GenerateCliReq struct {
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}
