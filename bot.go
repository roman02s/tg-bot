package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/go-telegram-bot-api/telegram-bot-api"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"log"
	"os"
	"time"
)

var (
	bot          *tgbotapi.BotAPI
	dbCollection *mongo.Collection
)

func main() {
	var err error

	// Создаем клиент для подключения к базе данных MongoDB
	mongoClient, err := mongo.NewClient(options.Client().ApplyURI(os.Getenv("MONGODB_URI")))
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = mongoClient.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// Проверяем подключение к базе данных
	err = mongoClient.Ping(ctx, readpref.Primary())
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Connected to MongoDB!")

	// Получаем доступ к коллекции пользователей
	dbCollection = mongoClient.Database("passwords").Collection("users")

	// Создаем бота с использованием токена
	bot, err = tgbotapi.NewBotAPI(os.Getenv("TELEGRAM_TOKEN"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Authorized on account %s", bot.Self.UserName)

	// Запускаем цикл обработки сообщений
	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates, err := bot.GetUpdatesChan(u)
	if err != nil {
		log.Fatal(err)
	}

	for update := range updates {
		if update.Message == nil {
			continue
		}

		// Обрабатываем команды пользователя
		switch update.Message.Text {
		case "/start":
			sendMessage(update.Message.Chat.ID, "Отправьте /set, чтобы добавить новый пароль, /get, чтобы получить существующий пароль или /del, чтобы удалить пароль.")
		case "/set":
			HandleSetPassword(update)
		case "/get":
			HandleGetPassword(update)
		case "/del":
			HandleDeletePassword(update)
		default:
			sendMessage(update.Message.Chat.ID, "Я не знаю такой команды")
		}
	}
}

type Password struct {
	Service string `bson:"service"`
	Login   string `bson:"login"`
	Hash    string `bson:"hash"`
	Expire  int64  `bson:"expire"`
}

type User struct {
	TelegramID int64      `bson:"telegram_id"`
	Passwords  []Password `bson:"passwords"`
}

func HandleSetPassword(update tgbotapi.Update) {
	chatID := update.Message.Chat.ID

	// Запрашиваем у пользователя данные о сервисе, логине и пароле
	sendMessage(chatID, "Введите название сервиса:")
	service := waitForUserResponse(chatID)

	sendMessage(chatID, "Введите логин:")
	login := waitForUserResponse(chatID)

	sendMessage(chatID, "Введите пароль:")
	password := waitForUserResponse(chatID)

	// Генерируем хеш пароля
	hash := generatePasswordHash(password)

	// Получаем текущее время и добавляем 24 часа для установки срока действия пароля
	expire := time.Now().Add(24 * time.Hour).Unix()

	// Создаем объект Password
	newPassword := Password{
		Service: service,
		Login:   login,
		Hash:    hash,
		Expire:  expire,
	}

	// Получаем текущего пользователя
	user := getUserByChatID(chatID)

	// Добавляем новый пароль к списку паролей пользователя
	user.Passwords = append(user.Passwords, newPassword)

	// Обновляем запись пользователя в базе данных
	updateUser(user)

	sendMessage(chatID, "Пароль успешно сохранен!")
}

func HandleGetPassword(update tgbotapi.Update) {
	chatID := update.Message.Chat.ID

	// Запрашиваем у пользователя название сервиса
	sendMessage(chatID, "Введите название сервиса:")
	service := waitForUserResponse(chatID)

	// Получаем текущего пользователя
	user := getUserByChatID(chatID)

	// Ищем пароль для указанного сервиса
	for _, password := range user.Passwords {
		if password.Service == service {
			// Проверяем срок действия пароля
			if password.Expire < time.Now().Unix() {
				sendMessage(chatID, "Срок действия пароля истек.")
				return
			}

			// Отправляем логин и пароль пользователю
			sendMessage(chatID, fmt.Sprintf("Логин: %s\nПароль: %s", password.Login, password.Hash))
			return
		}
	}

	sendMessage(chatID, "Пароль для указанного сервиса не найден.")
}

func HandleDeletePassword(update tgbotapi.Update) {
	chatID := update.Message.Chat.ID

	// Запрашиваем у пользователя название сервиса
	sendMessage(chatID, "Введите название сервиса:")
	service := waitForUserResponse(chatID)

	// Получаем текущего пользователя
	user := getUserByChatID(chatID)

	// Ищем пароль для указанного сервиса
	for i, password := range user.Passwords {
		if password.Service == service {
			// Удаляем пароль из списка паролей пользователя
			user.Passwords = append(user.Passwords[:i], user.Passwords[i+1:]...)

			// Обновляем запись пользователя в базе данных
			updateUser(user)

			sendMessage(chatID, "Пароль успешно удален.")
			return
		}
	}

	sendMessage(chatID, "Пароль для указанного сервиса не найден.")
}

func sendMessage(chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	_, err := bot.Send(msg)
	if err != nil {
		log.Println("Ошибка отправки сообщения:", err)
	}
}

func waitForUserResponse(chatID int64) string {
	// Ожидаем обновлений событий от пользователя
	updates := bot.ListenForWebhook("/" + bot.Token)
	defer bot.StopReceivingUpdates()

	// Ищем обновление, содержащее ответ от указанного чата
	for update := range updates {
		if update.Message != nil && update.Message.Chat.ID == chatID {
			return update.Message.Text
		}
	}

	return "" // В случае ошибки или истечения таймаута возвращаем пустую строку
}

func generatePasswordHash(password string) string {
	// Применяем хэш-функцию SHA256 к паролю
	hash := sha256.Sum256([]byte(password))

	// Преобразуем хэш в строку в шестнадцатеричном формате
	hashString := hex.EncodeToString(hash[:])

	return hashString
}

func getUserByChatID(chatID int64) *User {
	filter := bson.M{"telegram_id": chatID}

	var user User
	err := dbCollection.FindOne(context.Background(), filter).Decode(&user)
	if err != nil {
		log.Println("Ошибка при получении данных пользователя:", err)
	}

	return &user
}

func updateUser(user *User) {
	filter := bson.M{"telegram_id": user.TelegramID}
	update := bson.M{"$set": user}

	_, err := dbCollection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		log.Println("Ошибка при обновлении данных пользователя:", err)
	}
}
