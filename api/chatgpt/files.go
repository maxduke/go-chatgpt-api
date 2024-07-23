package chatgpt

import (
	"bytes"
	"encoding/json"
	http "github.com/bogdanfinn/fhttp"
	"io"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/maxduke/go-chatgpt-api/api"
	"github.com/linweiyuan/go-logger/logger"
	"strings"
)

func Files(c *gin.Context) {
	url := c.Request.URL.Path
	url = strings.ReplaceAll(url, api.ChatGPTApiPrefix, api.ChatGPTApiUrlPrefix)

	queryParams := c.Request.URL.Query().Encode()
	if queryParams != "" {
		url += "?" + queryParams
	}

	logger.Info(fmt.Sprintf("url: %s", url))

	// if not set, will return 404
	c.Status(http.StatusOK)

	var req *http.Request
	req, _ = NewRequest(http.MethodGet, url, nil, "", api.OAIDID)
	req.Header.Set(api.AuthorizationHeader, api.GetAccessToken(c))
	resp, err := api.Client.Do(req)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, api.ReturnMessage(err.Error()))
		return
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			logger.Error(fmt.Sprintf(api.AccountDeactivatedErrorMessage, c.GetString(api.EmailKey)))
		}

		responseMap := make(map[string]interface{})
		json.NewDecoder(resp.Body).Decode(&responseMap)
		c.AbortWithStatusJSON(resp.StatusCode, responseMap)
		return
	}

	var downloadURL DownloadURL
	err = json.NewDecoder(resp.Body).Decode(&downloadURL)
	if err == nil {
		logger.Info(fmt.Sprintf("downloadURL.Result: %s", downloadURL.Result))
		if !strings.HasPrefix(downloadURL.Result, "http") {
			redirectURL := api.ChatGPTApiUrlPrefix + downloadURL.Result
			logger.Info(fmt.Sprintf("redirectURL: %s", redirectURL))
			req, _ = NewRequest(http.MethodGet, redirectURL, nil, "", api.OAIDID)
			req.Header.Set(api.AuthorizationHeader, api.GetAccessToken(c))
			redirectResp, _ := api.Client.Do(req)
			logger.Info(fmt.Sprintf("redirectResp.StatusCode: %s", redirectResp.StatusCode))
			if redirectResp.StatusCode == http.StatusTemporaryRedirect { // 307 Temporary Redirect
				location := redirectResp.Header.Get("Location")
				logger.Info(fmt.Sprintf("location: %s", location))
				if location != "" {
					downloadURL.Result = location
					modifiedJSON, err := json.Marshal(downloadURL)
					if err == nil {
						resp.Body = io.NopCloser(bytes.NewBuffer(modifiedJSON))
					} else {
						fmt.Println("Error encoding JSON:", err)
					}
				}
			}
		}
	} else {
		fmt.Println("Error decoding JSON:", err)
	}

	io.Copy(c.Writer, resp.Body)
}
