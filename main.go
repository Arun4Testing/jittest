package main

import (
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	appID      = "vpaas-magic-cookie-aaf741963ad940d98be3754471b953ef"
	keyID      = "vpaas-magic-cookie-aaf741963ad940d98be3754471b953ef/fb4dde"
	privateKey *rsa.PrivateKey

	roomState = make(map[string]bool)
	mu        sync.Mutex
)

func main() {

	keyData, err := os.ReadFile("private.pem")
	if err != nil {
		log.Fatal("Cannot read private.pem")
	}

	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		log.Fatal("Invalid private key")
	}

	http.HandleFunc("/token", generateToken)

	fmt.Println("🚀 Server running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func generateToken(w http.ResponseWriter, r *http.Request) {

	room := r.URL.Query().Get("room")
	name := r.URL.Query().Get("name")

	if room == "" {
		http.Error(w, "room parameter required", http.StatusBadRequest)
		return
	}

	if name == "" {
		name = "Guest"
	}

	mu.Lock()
	isModerator := false

	if !roomState[room] {
		isModerator = true
		roomState[room] = true
	}

	mu.Unlock()

	claims := jwt.MapClaims{
		"aud": "jitsi",
		"iss": "chat",
		"sub": appID,
		"room": room,
		"exp": time.Now().Add(time.Hour).Unix(),
		"context": map[string]interface{}{
			"user": map[string]interface{}{
				"name":      name,
				"moderator": isModerator,
			},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		http.Error(w, "Token signing failed", http.StatusInternalServerError)
		return
	}

	w.Write([]byte(signedToken))
}