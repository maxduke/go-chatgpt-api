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
	"net"
	http2 "net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/PuerkitoBio/goquery"
	"golang.org/x/crypto/sha3"
	"golang.org/x/net/proxy"

	"github.com/maxduke/go-chatgpt-api/api"
	"github.com/linweiyuan/go-logger/logger"
)

var (
	autoContinue bool
	answers             = map[string]string{}
	timeLocation, _     = time.LoadLocation("Asia/Shanghai")
	timeLayout          = "Mon Jan 2 2006 15:04:05"
	cachedHardware = 0
	cachedScripts       = []string{}
	cachedDpl           = ""
	cachedRequireProof = ""

	PowRetryTimes = 0
	PowMaxDifficulty = "000032"
	powMaxCalcTimes = 500000
	navigatorKeys = []string{"hardwareConcurrency−16", "login−[object NavigatorLogin]","presentation−[object Presentation]","managed−[object NavigatorManagedData]"}
	documentKeys = []string{"location"}
	windowKeys = []string{
		"window",
		"self",
		"document",
		"name",
		"location",
		"customElements",
		"history",
		"navigation",
		"locationbar",
		"menubar",
		"personalbar",
		"scrollbars",
		"statusbar",
		"toolbar",
		"status",
		"closed",
		"frames",
		"length",
		"top",
		"opener",
		"parent",
		"frameElement",
		"navigator",
		"origin",
		"external",
		"screen",
		"innerWidth",
		"innerHeight",
		"scrollX",
		"pageXOffset",
		"scrollY",
		"pageYOffset",
		"visualViewport",
		"screenX",
		"screenY",
		"outerWidth",
		"outerHeight",
		"devicePixelRatio",
		"clientInformation",
		"screenLeft",
		"screenTop",
		"styleMedia",
		"onsearch",
		"isSecureContext",
		"trustedTypes",
		"performance",
		"onappinstalled",
		"onbeforeinstallprompt",
		"crypto",
		"indexedDB",
		"sessionStorage",
		"localStorage",
		"onbeforexrselect",
		"onabort",
		"onbeforeinput",
		"onbeforematch",
		"onbeforetoggle",
		"onblur",
		"oncancel",
		"oncanplay",
		"oncanplaythrough",
		"onchange",
		"onclick",
		"onclose",
		"oncontentvisibilityautostatechange",
		"oncontextlost",
		"oncontextmenu",
		"oncontextrestored",
		"oncuechange",
		"ondblclick",
		"ondrag",
		"ondragend",
		"ondragenter",
		"ondragleave",
		"ondragover",
		"ondragstart",
		"ondrop",
		"ondurationchange",
		"onemptied",
		"onended",
		"onerror",
		"onfocus",
		"onformdata",
		"oninput",
		"oninvalid",
		"onkeydown",
		"onkeypress",
		"onkeyup",
		"onload",
		"onloadeddata",
		"onloadedmetadata",
		"onloadstart",
		"onmousedown",
		"onmouseenter",
		"onmouseleave",
		"onmousemove",
		"onmouseout",
		"onmouseover",
		"onmouseup",
		"onmousewheel",
		"onpause",
		"onplay",
		"onplaying",
		"onprogress",
		"onratechange",
		"onreset",
		"onresize",
		"onscroll",
		"onsecuritypolicyviolation",
		"onseeked",
		"onseeking",
		"onselect",
		"onslotchange",
		"onstalled",
		"onsubmit",
		"onsuspend",
		"ontimeupdate",
		"ontoggle",
		"onvolumechange",
		"onwaiting",
		"onwebkitanimationend",
		"onwebkitanimationiteration",
		"onwebkitanimationstart",
		"onwebkittransitionend",
		"onwheel",
		"onauxclick",
		"ongotpointercapture",
		"onlostpointercapture",
		"onpointerdown",
		"onpointermove",
		"onpointerrawupdate",
		"onpointerup",
		"onpointercancel",
		"onpointerover",
		"onpointerout",
		"onpointerenter",
		"onpointerleave",
		"onselectstart",
		"onselectionchange",
		"onanimationend",
		"onanimationiteration",
		"onanimationstart",
		"ontransitionrun",
		"ontransitionstart",
		"ontransitionend",
		"ontransitioncancel",
		"onafterprint",
		"onbeforeprint",
		"onbeforeunload",
		"onhashchange",
		"onlanguagechange",
		"onmessage",
		"onmessageerror",
		"onoffline",
		"ononline",
		"onpagehide",
		"onpageshow",
		"onpopstate",
		"onrejectionhandled",
		"onstorage",
		"onunhandledrejection",
		"onunload",
		"crossOriginIsolated",
		"scheduler",
		"alert",
		"atob",
		"blur",
		"btoa",
		"cancelAnimationFrame",
		"cancelIdleCallback",
		"captureEvents",
		"clearInterval",
		"clearTimeout",
		"close",
		"confirm",
		"createImageBitmap",
		"fetch",
		"find",
		"focus",
		"getComputedStyle",
		"getSelection",
		"matchMedia",
		"moveBy",
		"moveTo",
		"open",
		"postMessage",
		"print",
		"prompt",
		"queueMicrotask",
		"releaseEvents",
		"reportError",
		"requestAnimationFrame",
		"requestIdleCallback",
		"resizeBy",
		"resizeTo",
		"scroll",
		"scrollBy",
		"scrollTo",
		"setInterval",
		"setTimeout",
		"stop",
		"structuredClone",
		"webkitCancelAnimationFrame",
		"webkitRequestAnimationFrame",
		"chrome",
		"caches",
		"cookieStore",
		"ondevicemotion",
		"ondeviceorientation",
		"ondeviceorientationabsolute",
		"launchQueue",
		"documentPictureInPicture",
		"getScreenDetails",
		"queryLocalFonts",
		"showDirectoryPicker",
		"showOpenFilePicker",
		"showSaveFilePicker",
		"originAgentCluster",
		"onpageswap",
		"onpagereveal",
		"credentialless",
		"speechSynthesis",
		"onscrollend",
		"webkitRequestFileSystem",
		"webkitResolveLocalFileSystemURL",
		"sendMsgToSolverCS",
		"webpackChunk_N_E",
		"__next_set_public_path__",
		"next",
		"__NEXT_DATA__",
		"__SSG_MANIFEST_CB",
		"__NEXT_P",
		"_N_E",
		"regeneratorRuntime",
		"__REACT_INTL_CONTEXT__",
		"DD_RUM",
		"_",
		"filterCSS",
		"filterXSS",
		"__SEGMENT_INSPECTOR__",
		"__NEXT_PRELOADREADY",
		"Intercom",
		"__MIDDLEWARE_MATCHERS",
		"__STATSIG_SDK__",
		"__STATSIG_JS_SDK__",
		"__STATSIG_RERENDER_OVERRIDE__",
		"_oaiHandleSessionExpired",
		"__BUILD_MANIFEST",
		"__SSG_MANIFEST",
		"__intercomAssignLocation",
		"__intercomReloadLocation"}
)

func init() {
	autoContinue = os.Getenv("AUTO_CONTINUE") == "true"
	cores := []int{8, 12, 16, 24}
	screens := []int{3000, 4000, 6000}
	rand.New(rand.NewSource(time.Now().UnixNano()))
	core := cores[rand.Intn(4)]
	rand.New(rand.NewSource(time.Now().UnixNano()))
	screen := screens[rand.Intn(3)]
	cachedHardware = core + screen
	envHardware := os.Getenv("HARDWARE")
	if envHardware != "" {
		intValue, err := strconv.Atoi(envHardware)
		if err != nil {
			logger.Error(fmt.Sprintf("Error converting %s to integer: %v", envHardware, err))
		} else {
			cachedHardware = intValue
			logger.Info(fmt.Sprintf("cachedHardware is set to : %d", cachedHardware))
		}
	}
	envPowRetryTimes := os.Getenv("POW_RETRY_TIMES")
	if envPowRetryTimes != "" {
		intValue, err := strconv.Atoi(envPowRetryTimes)
		if err != nil {
			logger.Error(fmt.Sprintf("Error converting %s to integer: %v", envPowRetryTimes, err))
		} else {
			PowRetryTimes = intValue
			logger.Info(fmt.Sprintf("PowRetryTimes is set to : %d", PowRetryTimes))
		}
	}
	envpowMaxDifficulty := os.Getenv("POW_MAX_DIFFICULTY")
	if envpowMaxDifficulty != "" {
		PowMaxDifficulty = envpowMaxDifficulty
		logger.Info(fmt.Sprintf("PowMaxDifficulty is set to : %s", PowMaxDifficulty))
	}
	envPowMaxCalcTimes := os.Getenv("POW_MAX_CALC_TIMES")
	if envPowMaxCalcTimes != "" {
		intValue, err := strconv.Atoi(envPowMaxCalcTimes)
		if err != nil {
			logger.Error(fmt.Sprintf("Error converting %s to integer: %v", envPowMaxCalcTimes, err))
		} else {
			powMaxCalcTimes = intValue
			logger.Info(fmt.Sprintf("PowMaxCalcTimes is set to : %d", powMaxCalcTimes))
		}
	}
}

func CreateConversation(c *gin.Context) {
	var request CreateConversationRequest

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

	// get accessToken
	authHeader := c.GetHeader(api.AuthorizationHeader)
	if strings.HasPrefix(authHeader, "Bearer") {
		authHeader = strings.Replace(authHeader, "Bearer ", "", 1)
	}
	chat_require := CheckRequire(authHeader, api.OAIDID)
	for i := 0; i < PowRetryTimes; i++ {		
		if chat_require.Proof.Required && chat_require.Proof.Difficulty <= PowMaxDifficulty {
			logger.Warn(fmt.Sprintf("Proof of work difficulty too high: %s. Retrying... %d/%d ", chat_require.Proof.Difficulty, i + 1, PowRetryTimes))
			chat_require = CheckRequire(authHeader, api.OAIDID)
		} else {
			break
		}
	}

	var arkoseToken string
	arkoseToken = c.GetHeader(api.ArkoseTokenHeader)
	if chat_require.Arkose.Required == true && arkoseToken == "" {
		token, err := GetArkoseTokenForModel(request.Model, chat_require.Arkose.DX)
		arkoseToken = token
		if err != nil || arkoseToken == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, api.ReturnMessage(err.Error()))
			return
		}
	}

	var proofToken string
	if chat_require.Proof.Required {
		proofToken = CalcProofToken(chat_require)
	}

	// TEST: force to use SSE
	request.ForceUseSse = true

	resp, done := sendConversationRequest(c, request, authHeader, api.OAIDID, arkoseToken, chat_require.Token, proofToken)
	if done {
		return
	}

	handleConversationResponse(c, resp, request, authHeader, api.OAIDID)
}

func sendConversationRequest(c *gin.Context, request CreateConversationRequest, accessToken string, deviceId string, arkoseToken string,  chat_token string, proofToken string) (*http.Response, bool) {
	apiUrl := api.ChatGPTApiUrlPrefix+"/backend-api/conversation"
	jsonBytes, _ := json.Marshal(request)
	req, err := NewRequest(http.MethodPost, apiUrl, bytes.NewReader(jsonBytes), accessToken, deviceId)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	if arkoseToken != "" {
		req.Header.Set("Openai-Sentinel-Arkose-Token", arkoseToken)
	}
	if chat_token != "" {
		req.Header.Set("Openai-Sentinel-Chat-Requirements-Token", chat_token)
	}
	if proofToken != "" {
		req.Header.Set("Openai-Sentinel-Proof-Token", proofToken)
	}
	req.Header.Set("Origin", api.ChatGPTApiUrlPrefix)
	if request.ConversationID != "" {
		req.Header.Set("Referer", api.ChatGPTApiUrlPrefix+"/c/"+request.ConversationID)
	} else {
		req.Header.Set("Referer", api.ChatGPTApiUrlPrefix+"/")
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

func handleConversationResponse(c *gin.Context, resp *http.Response, request CreateConversationRequest, accessToken string, deviceId string) {
	c.Writer.Header().Set("Content-Type", "text/event-stream; charset=utf-8")

	isMaxTokens := false
	continueParentMessageID := ""
	continueConversationID := ""

	var arkoseToken string
	var proofToken string

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
			if strings.HasPrefix(responseJson, "[DONE]") && isMaxTokens && autoContinue {
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

	if isMaxTokens && autoContinue {
		logger.Info("Continuing conversation")
		continueConversationRequest := CreateConversationRequest{
			ConversationMode:           request.ConversationMode,
			ForceNulligen:              request.ForceNulligen,
			ForceParagen:               request.ForceParagen,
			ForceParagenModelSlug:      request.ForceParagenModelSlug,
			ForceRateLimit:             request.ForceRateLimit,
			ForceUseSse:                request.ForceUseSse,
			HistoryAndTrainingDisabled: request.HistoryAndTrainingDisabled,
			Model:                      request.Model,
			ResetRateLimits:            request.ResetRateLimits,
			TimezoneOffsetMin:          request.TimezoneOffsetMin,

			Action:          actionContinue,
			ParentMessageID: continueParentMessageID,
			ConversationID:  continueConversationID,
			WebsocketRequestId: uuid.NewString(),
		}
		chat_require := CheckRequire(accessToken, deviceId)
		for i := 0; i < PowRetryTimes; i++ {		
			if chat_require.Proof.Required && chat_require.Proof.Difficulty <= PowMaxDifficulty {
				logger.Warn(fmt.Sprintf("Proof of work difficulty too high: %s. Retrying... %d/%d ", chat_require.Proof.Difficulty, i + 1, PowRetryTimes))
				chat_require = CheckRequire(accessToken, api.OAIDID)
			} else {
				break
			}
		}
 		if chat_require.Proof.Required {
 			proofToken = CalcProofToken(chat_require)
 		}
		if chat_require.Arkose.Required {
			token, err := GetArkoseTokenForModel(continueConversationRequest.Model, chat_require.Arkose.DX)
			arkoseToken = token
			if err != nil || arkoseToken == "" {
				c.AbortWithStatusJSON(http.StatusForbidden, api.ReturnMessage(err.Error()))
				return
			}
		}
		resp, done := sendConversationRequest(c, continueConversationRequest, accessToken, deviceId, arkoseToken, chat_require.Token, proofToken)
		if done {
			return
		}

		handleConversationResponse(c, resp, continueConversationRequest, accessToken, deviceId)
	}
}

func NewRequest(method string, url string, body io.Reader, token string, deviceId string) (*http.Request, error) {
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return &http.Request{}, err
	}
	request.Header.Set("User-Agent", api.UserAgent)
	request.Header.Set("Accept", "*/*")
	if deviceId != "" {
		request.Header.Set("Cookie", request.Header.Get("Cookie")+"oai-did="+deviceId+";")
		request.Header.Set("Oai-Device-Id", deviceId)
	}
	request.Header.Set("Oai-Language", api.Language)
	request.Header.Set("Cookie", request.Header.Get("Cookie")+"oai-dm-tgt-c-240329=2024-04-02;")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if api.PUID != "" {
		request.Header.Set("Cookie", "_puid="+api.PUID+";")
	}
	// if secret.TeamUserID != "" {
	// 	request.Header.Set("Chatgpt-Account-Id", secret.TeamUserID)
	// }
	return request, nil
}

func getWSURL(token string, deviceId string, retry int) (string, error) {
	request, err := NewRequest(http.MethodPost, api.ChatGPTApiUrlPrefix+"/backend-api/register-websocket", nil, token, deviceId)
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
		return getWSURL(token, deviceId, retry+1)
	}
	defer response.Body.Close()
	var WSSResp ChatGPTWSSResponse
	err = json.NewDecoder(response.Body).Decode(&WSSResp)
	if err != nil {
		return "", err
	}
	return WSSResp.WssUrl, nil
}

type rawDialer interface {
	Dial(network string, addr string) (c net.Conn, err error)
}

func CreateWSConn(addr string, connInfo *api.ConnInfo, retry int) error {
	dialer := websocket.Dialer{
		HandshakeTimeout: 8 * time.Second,
		NetDialTLSContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(addr)
			config := &tls.Config{ServerName: host, OmitEmptyPsk: true}
			var rawDial rawDialer
			if api.ProxyUrl != "" {
				proxyURL, _ := url.Parse(api.ProxyUrl)
				rawDial, _ = proxy.FromURL(proxyURL, proxy.Direct)
			} else {
				rawDial = &net.Dialer{}
			}
			dialConn, err := rawDial.Dial(network, addr)
			if err != nil {
				return nil, err
			}
			client := tls.UClient(dialConn, config, profiles.Okhttp4Android13.GetClientHelloId(), false, true)
			return client, nil
		},
	}
	dialer.EnableCompression = true
	dialer.Subprotocols = []string{"json.reliable.webpubsub.azure.v1"}
	conn, _, err := dialer.Dial(addr, nil)
	if err != nil {
		if retry > 3 {
			return err
		}
		time.Sleep(time.Second) // wait 1s to recreate w
		return CreateWSConn(addr, connInfo, retry+1)
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

func InitWSConn(token string, deviceId string, uuid string) error {
	connInfo := findAvailConn(token, uuid)
	conn := connInfo.Conn
	isExpired := connInfo.Expire.IsZero() || time.Now().After(connInfo.Expire)
	if conn == nil || isExpired {
		if conn != nil {
			connInfo.Ticker.Stop()
			conn.Close()
			connInfo.Conn = nil
		}
		wssURL, err := getWSURL(token, deviceId, 0)
		if err != nil {
			return err
		}
		err = CreateWSConn(wssURL, connInfo, 0)
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
				return InitWSConn(token, deviceId, uuid)
			case context.DeadlineExceeded:
				return nil
			default:
				return nil
			}
		}
		return nil
	}
}

func CheckRequire(access_token string, deviceId string) *ChatRequire {
	if cachedRequireProof == "" {
		cachedRequireProof = "gAAAAAC" + generateAnswer(strconv.FormatFloat(rand.Float64(), 'f', -1, 64), "0")
	}
	body := bytes.NewBuffer([]byte(`{"p":"` + cachedRequireProof + `"}`))
	var apiUrl string
	apiUrl = api.ChatGPTApiUrlPrefix+"/backend-api/sentinel/chat-requirements"
	request, err := NewRequest(http.MethodPost, apiUrl, body, access_token, deviceId)
	if err != nil {
		return nil
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", api.ChatGPTApiUrlPrefix)
	request.Header.Set("Referer", api.ChatGPTApiUrlPrefix+"/")
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
func GetDpl() {
	if len(cachedScripts) > 0 {
		return
	}
	cachedScripts = append(cachedScripts, "https://cdn.oaistatic.com/_next/static/chunks/9598-0150caea9526d55d.js?dpl=abad631f183104e6c8a323392d7bc30b933c5c7c")
	cachedDpl = "dpl=abad631f183104e6c8a323392d7bc30b933c5c7c"
	request, err := http.NewRequest(http.MethodGet, "https://chatgpt.com/?oai-dm=1", nil)
	request.Header.Set("User-Agent", api.UserAgent)
	request.Header.Set("Accept", "*/*")
	if err != nil {
		return
	}
	response, err := api.Client.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	doc, _ := goquery.NewDocumentFromReader(response.Body)
	scripts := []string{}
	doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
		src, exists := s.Attr("src")
		if exists {
			scripts = append(scripts, src)
			if cachedDpl == "" {
				idx := strings.Index(src, "dpl")
				if idx >= 0 {
					cachedDpl = src[idx:]
				}
			}
		}
	})
	if len(scripts) != 0 {
		cachedScripts = scripts
	}
}
func getConfig() []interface{} {	
	rand.New(rand.NewSource(time.Now().UnixNano()))
	script := cachedScripts[rand.Intn(len(cachedScripts))]
	timeNum := (float64(time.Since(api.StartTime).Nanoseconds()) + rand.Float64()) / 1e6
	rand.New(rand.NewSource(time.Now().UnixNano()))
	navigatorKey := navigatorKeys[rand.Intn(len(navigatorKeys))]
	rand.New(rand.NewSource(time.Now().UnixNano()))
	documentKey := documentKeys[rand.Intn(len(documentKeys))]
	rand.New(rand.NewSource(time.Now().UnixNano()))
	windowKey := windowKeys[rand.Intn(len(windowKeys))]
	return []interface{}{cachedHardware, getParseTime(), int64(4294705152), 0, api.UserAgent, script, cachedDpl, api.Language, api.Language+","+api.Language[:2], 0, navigatorKey, documentKey, windowKey, timeNum}
}

func CalcProofToken(require *ChatRequire) string {
    start := time.Now()
	proof := generateAnswer(require.Proof.Seed, require.Proof.Difficulty)
    elapsed := time.Since(start)
    // POW logging
	logger.Info(fmt.Sprintf("POW Difficulty: %s , took %v ms", require.Proof.Difficulty, elapsed.Milliseconds()))
	return "gAAAAAB" + proof
}

func generateAnswer(seed string, diff string) string {
	GetDpl()
	config := getConfig()
	diffLen := len(diff)
	hasher := sha3.New512()
	for i := 0; i < powMaxCalcTimes; i++ {
		config[3] = i
		config[9] = (i + 2) / 2
		json, _ := json.Marshal(config)
		base := base64.StdEncoding.EncodeToString(json)
		hasher.Write([]byte(seed + base))
		hash := hasher.Sum(nil)
		hasher.Reset()
		if hex.EncodeToString(hash[:diffLen])[:diffLen] <= diff {
			return base
		}
	}
	return "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D" + base64.StdEncoding.EncodeToString([]byte(`"`+seed+`"`))
}

func GetArkoseTokenForModel(model string, dx string) (string, error) {
	var api_version int
	if strings.HasPrefix(model, "gpt-4") {
		api_version = 4
	} else {
		api_version = 3
	}
	return api.GetArkoseToken(api_version, dx)
}