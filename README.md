# ghwebhookauth

[![Build Status](https://travis-ci.org/StefanKjartansson/ghwebhookauth.png?branch=master)](https://travis-ci.org/StefanKjartansson/ghwebhookauth)
[![Report Card](https://goreportcard.com/badge/github.com/StefanKjartansson/ghwebhookauth)](https://goreportcard.com/badge/github.com/StefanKjartansson/ghwebhookauth)
[![Coverage](http://gocover.io/_badge/github.com/StefanKjartansson/ghwebhookauth)](http://gocover.io/github.com/StefanKjartansson/ghwebhookauth)

A middleware that will check that a valid [X-Hub-Signature](https://developer.github.com/webhooks/securing/) header is sent for POST requests.

This module lets you secure webhook HTTP requests from GitHub in your Go Programming Language applications. 

## Installing

````bash
go get github.com/StefanKjartansson/ghwebhookauth
````

## Using it

You can use `ghwebhookauth ` with default `net/http` as follows.

````go
// main.go
package main

import (
  "net/http"
  "os"
  "github.com/StefanKjartansson/ghwebhookauth"
)

var webhookHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  // normal handler code
})

func main() {
  secretKey := os.Getenv("GITHUB_SECRET_KEY")
  gh := ghwebhookauth.New(secretKey)
  app := gh.Handler(http.HandlerFunc(webhookHandler))
  http.ListenAndServe("0.0.0.0:3000", app)
}
````

You can also use it with Negroni as follows:

````go
// main.go
package main

import (
  "net/http"
  "os"
  "github.com/StefanKjartansson/ghwebhookauth"
  "github.com/codegangsta/negroni"
  "github.com/gorilla/mux"
)

var webhookHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  // normal handler code
})

func main() {
  secretKey := os.Getenv("GITHUB_SECRET_KEY")
  gh := ghwebhookauth.New(secretKey)
  r := mux.NewRouter()
  r.Handle("/myhook", negroni.New(
    negroni.HandlerFunc(gh.HandlerWithNext),
    negroni.Wrap(webhookHandler),
  ))
  http.Handle("/", r)
  http.ListenAndServe(":3001", nil)
}
````
