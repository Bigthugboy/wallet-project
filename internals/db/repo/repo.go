package repo

import "github.com/Bigthugboy/wallet-project/internals"

type DBStore interface {
	InsertUser(user internals.User) (int64, error)
	SearchUserByEmail(email string) (int64, string, error)
	GetUserByID(userId string) (internals.User, error)
	SavePayment(transaction internals.Wallet) (int64, error)
	CreateWallet(User *internals.User) error
	GetAllTransactions(userId string) ([]internals.Wallet, error)
	GetTransactionWithID(userID, transactionID string) (internals.Wallet, error)
	UpdateWalletBalance(userID int, amount float64) error
	GetWalletBalance(userID, walletID string) (float64, error)
}
