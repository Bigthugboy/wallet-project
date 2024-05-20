package query

import (
	"github.com/Bigthugboy/wallet-project/config"

	"github.com/Bigthugboy/wallet-project/internals/db/repo"

	"github.com/jinzhu/gorm"
)

type WalletDB struct {
	App *config.AppTools
	DB  *gorm.DB
}

func NewWalletDB(app *config.AppTools, db *gorm.DB) repo.DBStore {
	return &WalletDB{
		App: app,
		DB:  db,
	}
}
