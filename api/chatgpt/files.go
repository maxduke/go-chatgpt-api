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
	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			logger.Error(fmt.Sprintf(api.AccountDeactivatedErrorMessage, c.GetString(api.EmailKey)))
		}

		responseMap := make(map[string]interface{})
		json.NewDecoder(bytes.NewBuffer(bodyBytes)).Decode(&responseMap)
		c.AbortWithStatusJSON(resp.StatusCode, responseMap)
		return
	}

	var download Download
	err = json.NewDecoder(bytes.NewBuffer(bodyBytes)).Decode(&download)
	if err == nil {
		logger.Info(fmt.Sprintf("download.DownloadURL: %s", download.DownloadURL))
		if !strings.HasPrefix(download.DownloadURL, "http") {
			redirectURL := api.ChatGPTApiUrlPrefix + download.DownloadURL
			logger.Info(fmt.Sprintf("redirectURL: %s", redirectURL))
			req, _ = NewRequest(http.MethodGet, redirectURL, nil, "", api.OAIDID)
			req.Header.Set(api.AuthorizationHeader, api.GetAccessToken(c))
			api.Client.SetFollowRedirect(false)
			redirectResp, _ := api.Client.Do(req)
			defer redirectResp.Body.Close()
			logger.Info(fmt.Sprintf("redirectResp.StatusCode: %v", redirectResp.StatusCode))
			if redirectResp.StatusCode == http.StatusTemporaryRedirect { // 307 Temporary Redirect
				location := redirectResp.Header.Get("Location")
				logger.Info(fmt.Sprintf("location: %s", location))
				if location != "" {
					download.DownloadURL = location
					modifiedJSON, err := json.Marshal(download)
					if err == nil {
						c.Writer.Write(modifiedJSON)
						return
					} else {
						logger.Error(fmt.Sprintf("Error encoding JSON: %v", err))
					}
				}
			}
		}
	} else {
		logger.Error(fmt.Sprintf("Error decoding JSON: %v", err))
	}

	c.Writer.Write(bodyBytes) 
}
