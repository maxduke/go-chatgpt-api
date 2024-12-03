package chatgpt

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/PuerkitoBio/goquery"
	"golang.org/x/crypto/sha3"

	"github.com/maxduke/go-chatgpt-api/api"
	"github.com/linweiyuan/go-logger/logger"
)

var (
	autoContinue bool
	answers             = map[string]string{}
	timeLocation, _     = time.LoadLocation("Asia/Shanghai")
	timeLayout          = "Mon Jan 2 2006 15:04:05"
	cachedHardware      = 0
	cachedSid           = uuid.NewString()
	cachedScripts       = []string{}
	cachedDpl           = ""
	cachedRequireProof = ""

	PowRetryTimes = 0
	PowMaxDifficulty = "000032"
	powMaxCalcTimes = 500000
	navigatorKeys = []string{
		"registerProtocolHandler−function registerProtocolHandler() { [native code] }",
		"storage−[object StorageManager]",
		"locks−[object LockManager]",
		"appCodeName−Mozilla",
		"permissions−[object Permissions]",
		"appVersion−5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
		"share−function share() { [native code] }",
		"webdriver−false",
		"managed−[object NavigatorManagedData]",
		"canShare−function canShare() { [native code] }",
		"vendor−Google Inc.",
		"vendor−Google Inc.",
		"mediaDevices−[object MediaDevices]",
		"vibrate−function vibrate() { [native code] }",
		"storageBuckets−[object StorageBucketManager]",
		"mediaCapabilities−[object MediaCapabilities]",
		"getGamepads−function getGamepads() { [native code] }",
		"bluetooth−[object Bluetooth]",
		"share−function share() { [native code] }",
		"cookieEnabled−true",
		"virtualKeyboard−[object VirtualKeyboard]",
		"product−Gecko",
		"mediaDevices−[object MediaDevices]",
		"canShare−function canShare() { [native code] }",
		"getGamepads−function getGamepads() { [native code] }",
		"product−Gecko",
		"xr−[object XRSystem]",
		"clipboard−[object Clipboard]",
		"storageBuckets−[object StorageBucketManager]",
		"unregisterProtocolHandler−function unregisterProtocolHandler() { [native code] }",
		"productSub−20030107",
		"login−[object NavigatorLogin]",
		"vendorSub−",
		"login−[object NavigatorLogin]",
		"userAgent−Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
		"getInstalledRelatedApps−function getInstalledRelatedApps() { [native code] }",
		"userAgent−Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
		"mediaDevices−[object MediaDevices]",
		"locks−[object LockManager]",
		"webkitGetUserMedia−function webkitGetUserMedia() { [native code] }",
		"vendor−Google Inc.",
		"xr−[object XRSystem]",
		"mediaDevices−[object MediaDevices]",
		"virtualKeyboard−[object VirtualKeyboard]",
		"userAgent−Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
		"virtualKeyboard−[object VirtualKeyboard]",
		"appName−Netscape",
		"storageBuckets−[object StorageBucketManager]",
		"presentation−[object Presentation]",
		"onLine−true",
		"mimeTypes−[object MimeTypeArray]",
		"credentials−[object CredentialsContainer]",
		"presentation−[object Presentation]",
		"getGamepads−function getGamepads() { [native code] }",
		"vendorSub−",
		"virtualKeyboard−[object VirtualKeyboard]",
		"serviceWorker−[object ServiceWorkerContainer]",
		"xr−[object XRSystem]",
		"product−Gecko",
		"keyboard−[object Keyboard]",
		"gpu−[object GPU]",
		"getInstalledRelatedApps−function getInstalledRelatedApps() { [native code] }",
		"webkitPersistentStorage−[object DeprecatedStorageQuota]",
		"doNotTrack",
		"clearAppBadge−function clearAppBadge() { [native code] }",
		"presentation−[object Presentation]",
		"serial−[object Serial]",
		"locks−[object LockManager]",
		"requestMIDIAccess−function requestMIDIAccess() { [native code] }",
		"locks−[object LockManager]",
		"requestMediaKeySystemAccess−function requestMediaKeySystemAccess() { [native code] }",
		"vendor−Google Inc.",
		"pdfViewerEnabled−true",
		"language−zh-CN",
		"setAppBadge−function setAppBadge() { [native code] }",
		"geolocation−[object Geolocation]",
		"userAgentData−[object NavigatorUAData]",
		"mediaCapabilities−[object MediaCapabilities]",
		"requestMIDIAccess−function requestMIDIAccess() { [native code] }",
		"getUserMedia−function getUserMedia() { [native code] }",
		"mediaDevices−[object MediaDevices]",
		"webkitPersistentStorage−[object DeprecatedStorageQuota]",
		"userAgent−Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
		"sendBeacon−function sendBeacon() { [native code] }",
		"hardwareConcurrency−32",
		"appVersion−5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
		"credentials−[object CredentialsContainer]",
		"storage−[object StorageManager]",
		"cookieEnabled−true",
		"pdfViewerEnabled−true",
		"windowControlsOverlay−[object WindowControlsOverlay]",
		"scheduling−[object Scheduling]",
		"pdfViewerEnabled−true",
		"hardwareConcurrency−32",
		"xr−[object XRSystem]",
		"userAgent−Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
		"webdriver−false",
		"getInstalledRelatedApps−function getInstalledRelatedApps() { [native code] }",
		"getInstalledRelatedApps−function getInstalledRelatedApps() { [native code] }",
		"bluetooth−[object Bluetooth]"}
	documentKeys = []string{"_reactListeningo743lnnpvdg", "location"}
	windowKeys = []string{
		"0",
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
	chat_require, p := CheckRequire(authHeader, api.OAIDID)
	if chat_require == nil {
		logger.Error("unable to check chat requirement")
		return
	}
	for i := 0; i < PowRetryTimes; i++ {		
		if chat_require.Proof.Required && chat_require.Proof.Difficulty <= PowMaxDifficulty {
			logger.Warn(fmt.Sprintf("Proof of work difficulty too high: %s. Retrying... %d/%d ", chat_require.Proof.Difficulty, i + 1, PowRetryTimes))
			chat_require, _ = CheckRequire(authHeader, api.OAIDID)
			if chat_require == nil {
				logger.Error("unable to check chat requirement")
				return
			}
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

	var turnstileToken string
	if chat_require.Turnstile.Required {
		turnstileToken = ProcessTurnstile(chat_require.Turnstile.DX, p)
	}

	// TEST: force to use SSE
	request.ForceUseSse = true

	resp, done := sendConversationRequest(c, request, authHeader, api.OAIDID, arkoseToken, chat_require.Token, proofToken, turnstileToken)
	if done {
		return
	}

	handleConversationResponse(c, resp, request, authHeader, api.OAIDID)
}

func sendConversationRequest(c *gin.Context, request CreateConversationRequest, accessToken string, deviceId string, arkoseToken string,  chat_token string, proofToken string, turnstileToken string) (*http.Response, bool) {
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
	if turnstileToken != "" {
		req.Header.Set("Openai-Sentinel-Turnstile-Token", turnstileToken)
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
	var turnstileToken string

	defer resp.Body.Close()
	reader := bufio.NewReader(resp.Body)

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
		chat_require, p := CheckRequire(accessToken, deviceId)
		if chat_require == nil {
			logger.Error("unable to check chat requirement")
			return
		}
		for i := 0; i < PowRetryTimes; i++ {		
			if chat_require.Proof.Required && chat_require.Proof.Difficulty <= PowMaxDifficulty {
				logger.Warn(fmt.Sprintf("Proof of work difficulty too high: %s. Retrying... %d/%d ", chat_require.Proof.Difficulty, i + 1, PowRetryTimes))
				chat_require, _ = CheckRequire(accessToken, api.OAIDID)
				if chat_require == nil {
					logger.Error("unable to check chat requirement")
					return
				}
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
		if chat_require.Turnstile.Required {
			turnstileToken = ProcessTurnstile(chat_require.Turnstile.DX, p)
		}
		resp, done := sendConversationRequest(c, continueConversationRequest, accessToken, deviceId, arkoseToken, chat_require.Token, proofToken, turnstileToken)
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

func CheckRequire(access_token string, deviceId string) (*ChatRequire, string) {
	if cachedRequireProof == "" {
		cachedRequireProof = "gAAAAAC" + generateAnswer(strconv.FormatFloat(rand.Float64(), 'f', -1, 64), "0")
	}
	body := bytes.NewBuffer([]byte(`{"p":"` + cachedRequireProof + `"}`))
	var apiUrl string
	apiUrl = api.ChatGPTApiUrlPrefix+"/backend-api/sentinel/chat-requirements"
	request, err := NewRequest(http.MethodPost, apiUrl, body, access_token, deviceId)
	if err != nil {
		return nil, ""
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", api.ChatGPTApiUrlPrefix)
	request.Header.Set("Referer", api.ChatGPTApiUrlPrefix+"/")
	response, err := api.Client.Do(request)
	if err != nil {
		return nil, ""
	}
	defer response.Body.Close()
	var require ChatRequire
	err = json.NewDecoder(response.Body).Decode(&require)
	if err != nil {
		logger.Error(err.Error())
		return nil, ""
	}
	return &require, cachedRequireProof
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
	cachedScripts = append(cachedScripts, "https://cdn.oaistatic.com/_next/static/cXh69klOLzS0Gy2joLDRS/_ssgManifest.js?dpl=453ebaec0d44c2decab71692e1bfe39be35a24b3")
	cachedDpl = "dpl=453ebaec0d44c2decab71692e1bfe39be35a24b3"
	request, err := http.NewRequest(http.MethodGet, "https://chatgpt.com", nil)
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
	return []interface{}{cachedHardware, getParseTime(), int64(4294705152), 0, api.UserAgent, script, cachedDpl, api.Language, api.Language+","+api.Language[:2], 0, navigatorKey, documentKey, windowKey, timeNum, cachedSid}
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