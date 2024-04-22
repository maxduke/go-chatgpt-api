package chatgpt

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	http2 "net/http"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/sha3"

	"github.com/maxduke/go-chatgpt-api/api"
	"github.com/linweiyuan/go-logger/logger"
)

var (
	answers             = map[string]string{}
	cores               = []int{8, 12, 16, 24}
	screens             = []int{3000, 4000, 6000}
	timeLocation, _     = time.LoadLocation("Asia/Shanghai")
	timeLayout          = "Mon Jan 2 2006 15:04:05"
)

func CreateConversation(c *gin.Context) {
	var request CreateConversationRequest
	var api_version int

	if err := c.BindJSON(&request); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, api.ReturnMessage(parseJsonErrorMessage))
		return
	}

	if len(request.Messages) != 0 {
		message := request.Messages[0]
		if message.Author.Role == "" {
			message.Author.Role = defaultRole
		}

		if message.Metadata == nil {
			message.Metadata = map[string]string{}
		}

		request.Messages[0] = message
	}

	if strings.HasPrefix(request.Model, gpt4Model) {
		api_version = 4
	} else {
		api_version = 3
	}

	// get accessToken
	authHeader := c.GetHeader(api.AuthorizationHeader)
	if strings.HasPrefix(authHeader, "Bearer") {
		authHeader = strings.Replace(authHeader, "Bearer ", "", 1)
	}
	chat_require := CheckRequire(authHeader)

	if chat_require.Arkose.Required == true && request.ArkoseToken == "" {
		arkoseToken, err := api.GetArkoseToken(api_version, chat_require.Arkose.DX)
		if err != nil || arkoseToken == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, api.ReturnMessage(err.Error()))
			return
		}

		request.ArkoseToken = arkoseToken
	}

	var proofToken string
	if chat_require.Proof.Required {
		proofToken = CalcProofToken(chat_require.Proof.Seed, chat_require.Proof.Difficulty)
	}

	resp, done := sendConversationRequest(c, request, chat_require.Token, proofToken)
	if done {
		return
	}

	handleConversationResponse(c, resp, request, chat_require.Token, proofToken, chat_require.Arkose.DX)
}

func sendConversationRequest(c *gin.Context, request CreateConversationRequest, chat_token string, proofToken string) (*http.Response, bool) {
	jsonBytes, _ := json.Marshal(request)
	req, _ := http.NewRequest(http.MethodPost, api.ChatGPTApiUrlPrefix+"/backend-api/conversation", bytes.NewBuffer(jsonBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", api.UserAgent)
	req.Header.Set(api.AuthorizationHeader, api.GetAccessToken(c))
	req.Header.Set("Accept", "text/event-stream")
	if request.ArkoseToken != "" {
		req.Header.Set("Openai-Sentinel-Arkose-Token", request.ArkoseToken)
	}
	if chat_token != "" {
		req.Header.Set("Openai-Sentinel-Chat-Requirements-Token", chat_token)
	}
	if proofToken != "" {
		req.Header.Set("Openai-Sentinel-Proof-Token", proofToken)
	}
	if api.PUID != "" {
		req.Header.Set("Cookie", "_puid="+api.PUID+";")
	}
	req.Header.Set("Oai-Language", api.Language)
	if api.OAIDID != "" {
		req.Header.Set("Cookie", req.Header.Get("Cookie")+"oai-did="+api.OAIDID)
		req.Header.Set("Oai-Device-Id", api.OAIDID)
	}
	resp, err := api.Client.Do(req)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, api.ReturnMessage(err.Error()))
		return nil, true
	}

	// 检查状态码是否大于299
	if resp.StatusCode > 299 {

		defer resp.Body.Close()

		// 设置响应头
		for name, values := range resp.Header {
			c.Writer.Header()[name] = values
		}
		c.Writer.WriteHeader(resp.StatusCode)

		// 直接转发响应体
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			logger.Error(err.Error())
		}

		c.Writer.Write(body)
		return nil, true
	}

	return resp, false
}

func handleConversationResponse(c *gin.Context, resp *http.Response, request CreateConversationRequest, chat_token string, proofToken string, dx string) {
	c.Writer.Header().Set("Content-Type", "text/event-stream; charset=utf-8")

	isMaxTokens := false
	continueParentMessageID := ""
	continueConversationID := ""

	defer resp.Body.Close()
	reader := bufio.NewReader(resp.Body)
	readStr, _ := reader.ReadString(' ')

	if !strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		var createConversationWssResponse ChatGPTWSSResponse
		json.Unmarshal([]byte(readStr), &createConversationWssResponse)
		wssUrl := createConversationWssResponse.WssUrl

		//fmt.Println(wssUrl)

		//wssu, err := url.Parse(wssUrl)

		//fmt.Println(wssu.RawQuery)

		wssSubProtocols := []string{"json.reliable.webpubsub.azure.v1"}

		dialer := websocket.DefaultDialer
		wssRequest, err := http.NewRequest("GET", wssUrl, nil)
		if err != nil {
			log.Fatal("Error creating request:", err)
		}
		wssRequest.Header.Add("Sec-WebSocket-Protocol", wssSubProtocols[0])

		conn, _, err := dialer.Dial(wssUrl, http2.Header(wssRequest.Header))
		if err != nil {
			log.Fatal("Error dialing:", err)
		}
		defer conn.Close()

		//log.Printf("WebSocket handshake completed with status code: %d", wssResp.StatusCode)

		recvMsgCount := 0

		for {
			messageType, message, err := conn.ReadMessage()
			if err != nil {
				log.Println("Error reading message:", err)
				break // Exit the loop on error
			}

			// Handle different types of messages (Text, Binary, etc.)
			switch messageType {
			case websocket.TextMessage:
				//log.Printf("Received Text Message: %s", message)
				var wssConversationResponse WSSMsgResponse
				json.Unmarshal(message, &wssConversationResponse)

				sequenceId := wssConversationResponse.SequenceId

				sequenceMsg := WSSSequenceAckMessage{
					Type:       "sequenceAck",
					SequenceId: sequenceId,
				}
				sequenceMsgStr, err := json.Marshal(sequenceMsg)

				base64Body := wssConversationResponse.Data.Body
				bodyByte, err := base64.StdEncoding.DecodeString(base64Body)

				if err != nil {
					return
				}
				body := string(bodyByte[:])

				if len(body) > 0 {
					c.Writer.Write([]byte(body))
					c.Writer.Flush()
				}

				if strings.Contains(body[:], "[DONE]") {
					conn.WriteMessage(websocket.TextMessage, sequenceMsgStr)
					conn.Close()
					return
				}

				recvMsgCount++

				if recvMsgCount > 10 {
					conn.WriteMessage(websocket.TextMessage, sequenceMsgStr)
				}
			case websocket.BinaryMessage:
				//log.Printf("Received Binary Message: %d bytes", len(message))
			default:
				//log.Printf("Received Other Message Type: %d", messageType)
			}
		}
	} else {
		for {
			if c.Request.Context().Err() != nil {
				break
			}

			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}

			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "event") ||
				strings.HasPrefix(line, "data: 20") ||
				strings.HasPrefix(line, `data: {"conversation_id"`) ||
				line == "" {
				continue
			}

			responseJson := line[6:]
			if strings.HasPrefix(responseJson, "[DONE]") && isMaxTokens && request.AutoContinue {
				continue
			}

			// no need to unmarshal every time, but if response content has this "max_tokens", need to further check
			if strings.TrimSpace(responseJson) != "" && strings.Contains(responseJson, responseTypeMaxTokens) {
				var createConversationResponse CreateConversationResponse
				json.Unmarshal([]byte(responseJson), &createConversationResponse)
				message := createConversationResponse.Message
				if message.Metadata.FinishDetails.Type == responseTypeMaxTokens && createConversationResponse.Message.Status == responseStatusFinishedSuccessfully {
					isMaxTokens = true
					continueParentMessageID = message.ID
					continueConversationID = createConversationResponse.ConversationID
				}
			}

			c.Writer.Write([]byte(line + "\n\n"))
			c.Writer.Flush()
		}
	}

	if isMaxTokens && request.AutoContinue {
		continueConversationRequest := CreateConversationRequest{
			HistoryAndTrainingDisabled: request.HistoryAndTrainingDisabled,
			Model:                      request.Model,
			TimezoneOffsetMin:          request.TimezoneOffsetMin,

			Action:          actionContinue,
			ParentMessageID: continueParentMessageID,
			ConversationID:  continueConversationID,
		}
		RenewTokenForRequest(&continueConversationRequest, dx)
		resp, done := sendConversationRequest(c, continueConversationRequest, chat_token, proofToken)
		if done {
			return
		}

		handleConversationResponse(c, resp, continueConversationRequest, chat_token, proofToken, dx)
	}
}

func getWSURL(token string, retry int) (string, error) {
	request, err := http.NewRequest(http.MethodPost, "https://chat.openai.com/backend-api/register-websocket", nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("User-Agent", api.UserAgent)
	request.Header.Set("Accept", "*/*")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := api.Client.Do(request)
	if err != nil {
		if retry > 3 {
			return "", err
		}
		time.Sleep(time.Second) // wait 1s to get ws url
		return getWSURL(token, retry+1)
	}
	defer response.Body.Close()
	var WSSResp ChatGPTWSSResponse
	err = json.NewDecoder(response.Body).Decode(&WSSResp)
	if err != nil {
		return "", err
	}
	return WSSResp.WssUrl, nil
}

func CreateWSConn(url string, connInfo *api.ConnInfo, retry int) error {
	dialer := websocket.DefaultDialer
	dialer.EnableCompression = true
	dialer.Subprotocols = []string{"json.reliable.webpubsub.azure.v1"}
	conn, _, err := dialer.Dial(url, nil)
	if err != nil {
		if retry > 3 {
			return err
		}
		time.Sleep(time.Second) // wait 1s to recreate w
		return CreateWSConn(url, connInfo, retry+1)
	}
	connInfo.Conn = conn
	connInfo.Expire = time.Now().Add(time.Minute * 30)
	ticker := time.NewTicker(time.Second * 8)
	connInfo.Ticker = ticker
	go func(ticker *time.Ticker) {
		defer ticker.Stop()
		for {
			<-ticker.C
			if err := connInfo.Conn.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
				connInfo.Conn.Close()
				connInfo.Conn = nil
				break
			}
		}
	}(ticker)
	return nil
}

func findAvailConn(token string, uuid string) *api.ConnInfo {
	for _, value := range api.ConnPool[token] {
		if !value.Lock {
			value.Lock = true
			value.Uuid = uuid
			return value
		}
	}
	newConnInfo := api.ConnInfo{Uuid: uuid, Lock: true}
	api.ConnPool[token] = append(api.ConnPool[token], &newConnInfo)
	return &newConnInfo
}

func FindSpecConn(token string, uuid string) *api.ConnInfo {
	for _, value := range api.ConnPool[token] {
		if value.Uuid == uuid {
			return value
		}
	}
	return &api.ConnInfo{}
}

func UnlockSpecConn(token string, uuid string) {
	for _, value := range api.ConnPool[token] {
		if value.Uuid == uuid {
			value.Lock = false
		}
	}
}

func InitWSConn(token string, uuid string) error {
	connInfo := findAvailConn(token, uuid)
	conn := connInfo.Conn
	isExpired := connInfo.Expire.IsZero() || time.Now().After(connInfo.Expire)
	if conn == nil || isExpired {
		if conn != nil {
			connInfo.Ticker.Stop()
			conn.Close()
			connInfo.Conn = nil
		}
		wssURL, err := getWSURL(token, 0)
		if err != nil {
			return err
		}
		CreateWSConn(wssURL, connInfo, 0)
		if err != nil {
			return err
		}
		return nil
	} else {
		ctx, cancelFunc := context.WithTimeout(context.Background(), time.Millisecond*100)
		go func() {
			defer cancelFunc()
			for {
				_, _, err := conn.NextReader()
				if err != nil {
					break
				}
				if ctx.Err() != nil {
					break
				}
			}
		}()
		<-ctx.Done()
		err := ctx.Err()
		if err != nil {
			switch err {
			case context.Canceled:
				connInfo.Ticker.Stop()
				conn.Close()
				connInfo.Conn = nil
				connInfo.Lock = false
				return InitWSConn(token, uuid)
			case context.DeadlineExceeded:
				return nil
			default:
				return nil
			}
		}
		return nil
	}
}

func CheckRequire(access_token string) *ChatRequire {
	request, err := http.NewRequest(http.MethodPost, "https://chat.openai.com/backend-api/sentinel/chat-requirements", bytes.NewBuffer([]byte(`{"conversation_mode_kind":"primary_assistant"}`)))
	if err != nil {
		return nil
	}
	if api.PUID != "" {
		request.Header.Set("Cookie", "_puid="+api.PUID+";")
	}
	request.Header.Set("Oai-Language", api.Language)
	if api.OAIDID != "" {
		request.Header.Set("Cookie", request.Header.Get("Cookie")+"oai-did="+api.OAIDID)
		request.Header.Set("Oai-Device-Id", api.OAIDID)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", api.UserAgent)
	if access_token != "" {
		request.Header.Set("Authorization", "Bearer "+access_token)
	}
	if err != nil {
		return nil
	}
	response, err := api.Client.Do(request)
	if err != nil {
		return nil
	}
	defer response.Body.Close()
	var require ChatRequire
	err = json.NewDecoder(response.Body).Decode(&require)
	if err != nil {
		return nil
	}
	return &require
}

type ProofWork struct {
	Difficulty string `json:"difficulty,omitempty"`
	Required   bool   `json:"required"`
	Seed       string `json:"seed,omitempty"`
}

func getParseTime() string {
	now := time.Now()
	now = now.In(timeLocation)
	return now.Format(timeLayout) + " GMT+0800 (中国标准时间)"
}
func getConfig() []interface{} {
	rand.New(rand.NewSource(time.Now().UnixNano()))
	core := cores[rand.Intn(4)]
	rand.New(rand.NewSource(time.Now().UnixNano()))
	screen := screens[rand.Intn(3)]
	return []interface{}{core + screen, getParseTime(), int64(4294705152), 0, api.DefaultUserAgent}

}
func CalcProofToken(seed string, diff string) string {
	if answers[seed] != "" {
		return answers[seed]
	}
	config := getConfig()
	diffLen := len(diff) / 2
	hasher := sha3.New512()
	for i := 0; i < 100000; i++ {
		config[3] = i
		json, _ := json.Marshal(config)
		base := base64.StdEncoding.EncodeToString(json)
		hasher.Write([]byte(seed + base))
		hash := hasher.Sum(nil)
		hasher.Reset()
		if hex.EncodeToString(hash[:diffLen]) <= diff {
			answers[seed] = "gAAAAAB" + base
			return answers[seed]
		}
	}
	return "gAAAAABwQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D" + base64.StdEncoding.EncodeToString([]byte(`"`+seed+`"`))
}

func RenewTokenForRequest(request *CreateConversationRequest, dx string) {
	var api_version int
	if strings.HasPrefix(request.Model, "gpt-4") {
		api_version = 4
	} else {
		api_version = 3
	}
	token, err := api.GetArkoseToken(api_version, dx)
	if err == nil {
		request.ArkoseToken = token
	} else {
		fmt.Println("Error getting Arkose token: ", err)
	}
}
