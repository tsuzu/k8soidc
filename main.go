package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"
	"os"

	"strings"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

var config struct {
	ClientID           string
	ClientSecret       string
	Scopes             []string
	RedirectURL        string
	ProviderURL        string
	SessionStoreSecret string
}

func init() {
	config.ClientID = os.Getenv("OIDC_CLIENT_ID")
	config.ClientSecret = os.Getenv("OIDC_CLIENT_SECRET")
	config.Scopes = strings.Split(os.Getenv("OIDC_SCOPES"), ",")
	config.RedirectURL = os.Getenv("OIDC_REDIRECT_URL")
	config.ProviderURL = os.Getenv("OIDC_PROVIDER_URL")
	config.SessionStoreSecret = os.Getenv("SESSION_STORE_SECRET")

	if config.SessionStoreSecret == "" {
		config.SessionStoreSecret = "very-secure-secret"
	}
}

type Authenticator struct {
	Provider *oidc.Provider
	Config   oauth2.Config
	Ctx      context.Context
}

func NewAuthenticator() (*Authenticator, error) {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, config.ProviderURL)
	if err != nil {
		log.Printf("failed to get provider: %v", err)
		return nil, err
	}

	conf := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       config.Scopes,
	}

	return &Authenticator{
		Provider: provider,
		Config:   conf,
		Ctx:      ctx,
	}, nil
}

func CallbackHandler(w http.ResponseWriter, r *http.Request) {
	session, err := Store.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if r.URL.Query().Get("state") != session.Values["state"] {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	authenticator, err := NewAuthenticator()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	token, err := authenticator.Config.Exchange(context.TODO(), r.URL.Query().Get("code"))
	if err != nil {
		log.Printf("no token found: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}

	oidcConfig := &oidc.Config{
		ClientID: config.ClientID,
	}

	idToken, err := authenticator.Provider.Verifier(oidcConfig).Verify(context.TODO(), rawIDToken)

	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Getting now the userInfo
	var profile map[string]interface{}
	if err := idToken.Claims(&profile); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["id_token"] = rawIDToken
	session.Values["access_token"] = token.AccessToken
	session.Values["refresh_token"] = token.RefreshToken
	session.Values["profile"] = profile
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect to logged in page
	http.Redirect(w, r, "/user", http.StatusSeeOther)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Generate random state
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	state := base64.StdEncoding.EncodeToString(b)

	session, err := Store.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.Values["state"] = state
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	authenticator, err := NewAuthenticator()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authenticator.Config.AuthCodeURL(state), http.StatusTemporaryRedirect)
}

func UserinfoHandler(rw http.ResponseWriter, req *http.Request) {
	session, err := Store.Get(req, "auth-session")
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	if session.IsNew {
		http.Redirect(rw, req, "/login", http.StatusTemporaryRedirect)

		return
	}

	idTokenI, ok := session.Values["id_token"]

	if !ok {
		http.Redirect(rw, req, "/login", http.StatusTemporaryRedirect)

		return
	}

	idToken := idTokenI.(string)

	refreshTokenI, ok := session.Values["refresh_token"]

	if !ok {
		http.Redirect(rw, req, "/login", http.StatusTemporaryRedirect)

		return
	}

	refreshToken := refreshTokenI.(string)

	type Config struct {
		ClientID                string `yaml:"client-id"`
		ClientSecret            string `yaml:"client-secret"`
		IDToken                 string `yaml:"id-token"`
		IdpCertificateAuthority string `yaml:"idp-certificate-authority,omitempty"`
		IdpIssuerURL            string `yaml:"idp-issuer-url"`
		RefreshToken            string `yaml:"refresh-token"`
	}

	type AuthProvider struct {
		Config *Config `yaml:"config"`
		Name   string  `yaml:"name"`
	}

	type UserConfig struct {
		AuthProvider *AuthProvider `yaml:"auth-provider"`
	}

	type User struct {
		Name string      `yaml:"name"`
		User *UserConfig `yaml:"user"`
	}

	type UserContext struct {
		Users []*User `yaml:"users"`
	}

	uc := &UserContext{
		Users: []*User{
			{
				Name: "openid-connect",
				User: &UserConfig{
					AuthProvider: &AuthProvider{
						Name: "oidc",
						Config: &Config{
							ClientID:     config.ClientID,
							ClientSecret: config.ClientSecret,
							IDToken:      idToken,
							IdpIssuerURL: config.ProviderURL,
							RefreshToken: refreshToken,
						},
					},
				},
			},
		},
	}

	rw.Header().Set("Content-Tyep", "application/yaml;charset=UTF-8")
	encoder := yaml.NewEncoder(rw)
	encoder.SetIndent(2)
	encoder.Encode(uc)
}

func main() {
	Init()

	mux := http.NewServeMux()
	mux.HandleFunc("/login", LoginHandler)
	mux.HandleFunc("/callback", CallbackHandler)
	mux.HandleFunc("/userinfo", UserinfoHandler)

	mux.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		if req.Method != "GET" && req.URL.Path != "/" {
			http.NotFound(rw, req)

			return
		}

		session, err := Store.Get(req, "auth-session")

		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		session.Save(req, rw)

		_, found := session.Values["id_token"]

		if found {
			http.Redirect(rw, req, "/userinfo", http.StatusTemporaryRedirect)
		} else {
			http.Redirect(rw, req, "/login", http.StatusTemporaryRedirect)
		}
	})

	port := "80"

	if p, found := os.LookupEnv("PORT"); found {
		port = p
	}

	http.ListenAndServe(":"+port, mux)
}
