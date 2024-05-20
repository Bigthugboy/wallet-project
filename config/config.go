package config

import (
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
