package main

import (
	"encoding/gob"
	"log"

	"github.com/Bigthugboy/wallet-project/cmd/routes"
	"github.com/Bigthugboy/wallet-project/config"
	"github.com/Bigthugboy/wallet-project/internals"
	"github.com/Bigthugboy/wallet-project/internals/controller"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"
)

var app = config.NewAppTools()

func main() {
	gob.Register(internals.User{})
	gob.Register(internals.Wallet{})
	data, err := config.LoadConfig(".")
	if err != nil {
		log.Println("fails to load env")
	}
	//dsn := "root:damilola@tcp(127.0.0.1:3306)/wallet-project?charset=utf8mb4&parseTime=True&loc=Local"

	db, err := gorm.Open("mysql", data.DNS)
	if err != nil {
		log.Fatalf("failed to connect to the database: %v", err)
		panic(err)
	}

	db.AutoMigrate(&internals.User{}, &internals.Wallet{})

	app.InfoLogger.Println("*---------- Connecting to the wallet database --------")
	app.InfoLogger.Println("*---------- Starting Wallet Web Server -----------*")
	app.InfoLogger.Println("*---------- Connected to Wallet Web Server -----------*")

	srv := controller.NewWallet(app, db)

	r := gin.Default()
	routes.SetupRoutes(r, srv)

	if err := r.Run("localhost:9090"); err != nil {
		log.Fatal(err)
	}

}
