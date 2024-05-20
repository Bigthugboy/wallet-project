package query

import (
	"errors"
	"fmt"
	"log"

	"github.com/Bigthugboy/wallet-project/internals"
	"github.com/jinzhu/gorm"
)

func (w *WalletDB) InsertUser(user internals.User) (int64, error) {
	if w.DB == nil {
		return -1, fmt.Errorf("database connection is not initialized")
	}

	var existingUser internals.User
	if err := w.DB.Where("email = ?", user.Email).First(&existingUser).Error; err != nil && err != gorm.ErrRecordNotFound {
		return -1, err
	}
	if existingUser.ID != 0 {
		return -1, fmt.Errorf("user with email '%s' already exists", user.Email)
	}
	result := w.DB.Create(&user)
	if err := result.Error; err != nil {
		return -1, err
	}

	return result.RowsAffected, nil
}

func (w *WalletDB) SearchUserByEmail(email string) (int64, string, error) {
	if w.DB == nil {
		return -1, "", fmt.Errorf("database connection is not initialized")
	}

	user := internals.User{}
	if err := w.DB.Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return -1, "", nil
		}
		return -1, "", err
	}

	return int64(user.ID), user.FirstName, nil
}

func (wa *WalletDB) CreateWallet(user *internals.User) error {
	wallet := &internals.Wallet{UserID: int(user.ID)}
	if err := wa.DB.Create(&wallet).Error; err != nil {
		return err
	}
	user.Wallet = *wallet
	return nil
}

func (wa *WalletDB) GetAllTransactions(userID string) ([]internals.Wallet, error) {
	var user internals.User
	if err := wa.DB.Preload("Wallet").First(&user, userID).Error; err != nil {
		return nil, fmt.Errorf("failed to find user: %v", err)
	}
	var transactions []internals.Wallet
	if err := wa.DB.Model(&user.Wallet).Related(&transactions).Error; err != nil {
		return nil, fmt.Errorf("failed to get transactions: %v", err)
	}
	return transactions, nil
}

func (wa *WalletDB) GetTransactionWithID(userID, WalletID string) (internals.Wallet, error) {
	var user internals.User
	if err := wa.DB.Preload("Wallet").First(&user, userID).Error; err != nil {
		return internals.Wallet{}, fmt.Errorf("failed to find user: %v", err)
	}
	var transaction internals.Wallet
	if err := wa.DB.Where("id = ? ", WalletID).First(&transaction).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			return internals.Wallet{}, fmt.Errorf("transaction not found with ID %s", WalletID)
		}
		return internals.Wallet{}, fmt.Errorf("failed to get transaction: %v", err)
	}
	return transaction, nil
}

func (w *WalletDB) GetUserByID(userId string) (internals.User, error) {
	user := internals.User{}
	if w.DB == nil {
		return user, fmt.Errorf("database connection is not initialized")
	}
	if err := w.DB.Where("ID = ?", userId).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return user, fmt.Errorf("user not found with ID %s", userId)
		}
		return user, err
	}

	return user, nil
}
func (w *WalletDB) SavePayment(transaction internals.Wallet) (int64, error) {
	result := w.DB.Create(&transaction)
	if err := result.Error; err != nil {
		return -1, err
	}

	return result.RowsAffected, nil
}

func (w *WalletDB) UpdateWalletBalance(userID int, amount float64) error {
	// Start a transaction
	tx := w.DB.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	var wallet internals.Wallet
	if err := tx.Where("user_id = ?", userID).First(&wallet).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			tx.Rollback()
			return err
		}
		tx.Rollback()
		return err
	}
	newBalance := wallet.Balance + amount
	if newBalance < 0 {
		tx.Rollback()
		return errors.New("insufficient funds")
	}
	wallet.Balance = newBalance
	if err := tx.Save(&wallet).Error; err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit().Error; err != nil {
		return err
	}

	return nil
}

func (w *WalletDB) GetWalletBalance(userID, walletID string) (float64, error) {
	var user internals.User
	if err := w.DB.Preload("Wallet").First(&user, userID).Error; err != nil {
		log.Println("Error retrieving user:", err)
		return -1, err
	}
	balance := user.Wallet.Balance
	return balance, nil
}
