package main

import (
	"encoding/gob"

	"github.com/gorilla/sessions"
)

var (
	Store *sessions.CookieStore
)

func Init() error {
	Store = sessions.NewCookieStore([]byte(config.SessionStoreSecret))
	gob.Register(map[string]interface{}{})
	return nil
}
