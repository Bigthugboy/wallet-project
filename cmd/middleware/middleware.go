package middleware

import (
	"log"
	"net/http"
	"strings"

	"github.com/Bigthugboy/wallet-project/internals/security"
	"github.com/gin-gonic/gin"
)

func Authenticate() gin.HandlerFunc {
	log.Print("log authentication process")
	return func(c *gin.Context) {
		log.Print("check authorization")
		authHeader := c.GetHeader("Authorization")
		log.Println(authHeader)
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			return
		}
		log.Print("split token from bearer")

		parts := strings.Split(authHeader, " ")
		log.Print(parts)
		if len(parts) != 2 || parts[0] != "Bearer" {
			log.Println(parts[0])
			log.Println(parts[1])

			log.Print(len(parts[0]))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			return
		}
		log.Println(" print token to be passed")
		tokenString := parts[1]

		_, err := security.Parse(tokenString)
		log.Print("token passed is " + tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: " + err.Error()})
			return
		}
		c.Next()
	}
}
