package main

import (
	"context"
	"encoding/json"
	"fmt"
	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"os"
)

func main() {
	ctx := context.Background()

	clientID := os.Getenv("CLIENTID")
	clientSecret := os.Getenv("CLIENTSECRET")
	issuer := os.Getenv("ISSUER")

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		log.Fatal(err)
	}

	config := oauth2.Config{
		ClientID: clientID,
		ClientSecret: clientSecret,
		Endpoint:    provider.Endpoint(),
		RedirectURL: "http://192.168.1.117:8081/auth/callback",
		Scopes:      []string{oidc.ScopeOpenID, "profile", "email", "roles", "openid"},
	}

	state := "123"

	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, config.AuthCodeURL(state), http.StatusFound)
	})

	http.HandleFunc("/auth/callback", func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("state") != state {
			http.Error(writer, "State inválido", http.StatusBadGateway)
			return
		}
		fmt.Println(request.URL)
		fmt.Println(request.URL.Query().Get("code"))
		token, err := config.Exchange(ctx, request.URL.Query().Get("code"))
		if err != nil {
			http.Error(writer, "Falha ao trocar o token", http.StatusInternalServerError)
			return
		}

		idToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(writer, "Falha ao gerar o IDToken", http.StatusInternalServerError)
			return
		}

		userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			http.Error(writer, "Erro no UserInfo", http.StatusInternalServerError)
			return
		}

		resp := struct {
			AccessToken *oauth2.Token
			IDToken     string
			UserInfo    *oidc.UserInfo
		}{
			token,
			idToken,
			userInfo,
		}

		data, err := json.Marshal(resp)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		writer.Write(data)
	})

	log.Fatal(http.ListenAndServe(":8081", nil))
}
