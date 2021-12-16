package api

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

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

			c.JSON(http.StatusOK, gin.H{
				"code":    0,
				"message": "ok",
				"data": gin.H{
					"sk":        "sk",
					"pk":        "pk",
					"signature": "signature",
					"cost":      10,
					"algorithm": c.Param("algorithm"),
				},
			})
		})
	}
}
