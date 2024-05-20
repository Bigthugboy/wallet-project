package internals

import "github.com/gin-gonic/gin"

type Service interface {
	RegisterHandler() gin.HandlerFunc
	MakePayment() gin.HandlerFunc
	LoginHandler() gin.HandlerFunc
	ValidatePayment() gin.HandlerFunc
	TransactionHistory() gin.HandlerFunc
	GetTransactionWithID() gin.HandlerFunc
	CheckBalance() gin.HandlerFunc
	GetExchangeRate() gin.HandlerFunc
}
