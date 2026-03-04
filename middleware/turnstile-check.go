package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

type turnstileCheckResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
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

			primaryParam := "turnstile"
			fallbackParam := "hcaptcha"
			if provider == "hcaptcha" {
				primaryParam = "hcaptcha"
				fallbackParam = "turnstile"
			}

			response := c.Query("captcha")
			if response == "" {
				response = c.Query(primaryParam)
			}
			if response == "" {
				// Backward compatibility with the other provider-specific parameter.
				response = c.Query(fallbackParam)
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
			if secret == "" {
				message := "Turnstile Secret Key 为空，请联系管理员配置"
				if provider == "hcaptcha" {
					message = "hCaptcha Secret Key 为空，请联系管理员配置"
				}
				c.JSON(http.StatusOK, gin.H{
					"success": false,
					"message": message,
				})
				c.Abort()
				return
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
				if len(res.ErrorCodes) > 0 {
					common.SysLog("captcha verification failed, provider=" + provider + ", error_codes=" + strings.Join(res.ErrorCodes, ","))
				} else {
					common.SysLog("captcha verification failed, provider=" + provider)
				}
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
