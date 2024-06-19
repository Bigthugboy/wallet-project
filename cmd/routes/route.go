package routes

import (
	"github.com/Bigthugboy/wallet-project/cmd/middleware"
	"github.com/Bigthugboy/wallet-project/internals"
	"github.com/gin-gonic/gin"
)

func SetupRoutes(r *gin.Engine, service internals.Service) {
	// Register routes
	r.POST("/register", service.RegisterHandler())
	r.POST("/login", service.LoginHandler())
	r.POST("/generate", service.GenerateHandler())

	protectedRouter := r.Group("/api/auth")
	protectedRouter.Use(middleware.AuthMiddleware())
	{
		protectedRouter.POST("/payment", service.MakePayment())
		protectedRouter.POST("/validate-payment", service.ValidatePayment())
		protectedRouter.GET("/transactions/:userID/:transactionID", service.GetTransactionWithID())
		protectedRouter.GET("/balance/:userID/:walletID", service.CheckBalance())
		protectedRouter.GET("/exchange-rate", service.GetExchangeRate())
	}

}
