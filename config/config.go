package config

import (
	"github.com/spf13/viper"
	"log"
	"os"

	"github.com/go-playground/validator"
)

type AppTools struct {
	ErrorLogger *log.Logger
	InfoLogger  *log.Logger
	Validate    *validator.Validate
}

func NewAppTools() *AppTools {
	return &AppTools{
		log.New(os.Stdout, "[ Error ]", log.LstdFlags|log.Lshortfile),
		log.New(os.Stdout, "[ info ]", log.LstdFlags|log.Lshortfile),
		validator.New(),
	}
}

type Data struct {
	AuthToken string `mapstructure:"AUTHTOKEN"`
	SecretKey string `mapstructure:"SECRETKEY"`
	PublicKey string `mapstructure:"PUBLICKEY"`
	DNS       string `mapstructure:"DNS"`
}

func LoadConfig(path string) (data Data, err error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("app")
	viper.SetConfigType("env")

	viper.AutomaticEnv()

	err = viper.ReadInConfig()
	if err != nil {
		log.Fatal("Error reading config file")
		return
	}
	err = viper.Unmarshal(&data)
	return
}
