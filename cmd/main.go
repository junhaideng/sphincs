package main

import "github.com/junhaideng/sphincs/api"

func main() {
	app := api.New()
	app.Run(":8080")
}
