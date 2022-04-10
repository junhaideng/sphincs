package api

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

var signatureAlgorithms = []string{LAMPORT, HORS, HORST, SPHINCS, WOTS, WOTSPLUS}

func New() *gin.Engine {
	app := gin.New()
	setup(app)
	return app
}

// Cors 设置跨域请求
func cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method

		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Headers", "Content-Type,AccessToken,X-CSRF-Token, Authorization, Token")
		c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE,UPDATE") //服务器支持的所有跨域请求的方
		c.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers, Content-Type")
		c.Header("Access-Control-Allow-Credentials", "true")

		//放行所有OPTIONS方法
		if method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
		}
		// 处理请求
		c.Next()
	}
}

func setup(app *gin.Engine) {
	app.Use(cors())
	api := app.Group("/api")

	// TODO: test
	{
		api.POST("/signature/:algorithm", func(c *gin.Context) {
			start := time.Now()
			r, err := GenSignature(c.Param("algorithm"), []byte(c.Param("message")))
			//fmt.Printf("%#v\n", r)
			if err != nil {
				c.JSON(http.StatusOK, gin.H{
					"code":    -1,
					"message": err.Error(),
					"data":    nil,
				})
				return
			}
			c.JSON(http.StatusOK, gin.H{
				"code":    0,
				"message": "ok",
				"data":    r,
			})
			fmt.Printf("algorithm: %x, time: %s\n", c.Param("algorithm"), time.Now().Sub(start))
		})

		api.GET("/signature/list", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"code":    0,
				"message": "ok",
				"data":    signatureAlgorithms,
			})
		})
	}
}
