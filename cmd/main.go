package main

import (
	"fmt"

	"github.com/junhaideng/sphincs/api"
)

func main() {
	app := api.New()
	err := app.Run(":8080")
	if err != nil {
		fmt.Println("运行后端失败：", err)
		return
	}
}
