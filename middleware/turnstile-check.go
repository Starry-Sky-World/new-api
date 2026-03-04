package middleware

import (
	"net/http"
	"net/url"

	"github.com/QuantumNous/new-api/common"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

type turnstileCheckResponse struct {
	Success bool `json:"success"`
}

func TurnstileCheck() gin.HandlerFunc {
	return func(c *gin.Context) {
		if common.TurnstileCheckEnabled {
			session := sessions.Default(c)
			captchaChecked := session.Get("captcha")
			legacyTurnstileChecked := session.Get("turnstile")
			if captchaChecked != nil || legacyTurnstileChecked != nil {
				c.Next()
				return
			}

			provider := common.CaptchaProvider
			if provider != "hcaptcha" {
				provider = "turnstile"
			}

			response := c.Query("captcha")
			if response == "" {
				if provider == "hcaptcha" {
					response = c.Query("hcaptcha")
				} else {
					response = c.Query("turnstile")
				}
			}
			if response == "" {
				// Backward and forward compatibility.
				response = c.Query("turnstile")
			}
			if response == "" {
				response = c.Query("hcaptcha")
			}
			if response == "" {
				message := "Turnstile token 为空"
				if provider == "hcaptcha" {
					message = "hCaptcha token 为空"
				}
				c.JSON(http.StatusOK, gin.H{
					"success": false,
					"message": message,
				})
				c.Abort()
				return
			}

			verifyURL := "https://challenges.cloudflare.com/turnstile/v0/siteverify"
			secret := common.TurnstileSecretKey
			if provider == "hcaptcha" {
				verifyURL = "https://hcaptcha.com/siteverify"
				secret = common.HCaptchaSecretKey
			}

			rawRes, err := http.PostForm(verifyURL, url.Values{
				"secret":   {secret},
				"response": {response},
				"remoteip": {c.ClientIP()},
			})
			if err != nil {
				common.SysLog(err.Error())
				c.JSON(http.StatusOK, gin.H{
					"success": false,
					"message": err.Error(),
				})
				c.Abort()
				return
			}
			defer rawRes.Body.Close()
			var res turnstileCheckResponse
			err = common.DecodeJson(rawRes.Body, &res)
			if err != nil {
				common.SysLog(err.Error())
				c.JSON(http.StatusOK, gin.H{
					"success": false,
					"message": err.Error(),
				})
				c.Abort()
				return
			}
			if !res.Success {
				message := "Turnstile 校验失败，请刷新重试！"
				if provider == "hcaptcha" {
					message = "hCaptcha 校验失败，请刷新重试！"
				}
				c.JSON(http.StatusOK, gin.H{
					"success": false,
					"message": message,
				})
				c.Abort()
				return
			}
			session.Set("captcha", true)
			err = session.Save()
			if err != nil {
				c.JSON(http.StatusOK, gin.H{
					"message": "无法保存会话信息，请重试",
					"success": false,
				})
				return
			}
		}
		c.Next()
	}
}
