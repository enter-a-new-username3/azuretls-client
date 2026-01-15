package main

/*
#include <stdlib.h>
#include <string.h>

// Response structure for C
typedef struct {
    int status_code;
    char* body;
    int body_len;
    char* headers;
    char* url;
    char* error;
    char* protocol;
} CFfiResponse;

// Request structure for C
typedef struct {
    char* method;
    char* url;
    char* body;
    char* headers;
    char* proxy;
    int timeout_ms;
    int force_http1;
    int force_http3;
    int ignore_body;
    int no_cookie;
    int disable_redirects;
    int max_redirects;
    int insecure_skip_verify;
} CFfiRequest;

// Session configuration structure
typedef struct {
    char* browser;
    char* user_agent;
    char* proxy;
    int timeout_ms;
    int max_redirects;
    int insecure_skip_verify;
    char* headers;
} CFfiSessionConfig;
*/
import "C"

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"runtime"
	"sync"
	"time"
	"unsafe"

	tls "github.com/Noooste/utls"

	http "github.com/Noooste/fhttp"

	"github.com/enter-a-new-username3/azuretls-client"
)

// Version information - will be set during build
var Version = "dev"

type Closable interface {
	Close() error // or Close() if it returns nothing
}

// SessionManager manages active sessions with thread safety
type SessionManager[T Closable] struct {
	mu       sync.RWMutex
	sessions map[uintptr]T
	nextID   uintptr
}

var sessionManager = &SessionManager[*azuretls.Session]{
	sessions: make(map[uintptr]*azuretls.Session),
	nextID:   1,
}

var websocketSessionManager = &SessionManager[*azuretls.Websocket]{
	sessions: make(map[uintptr]*azuretls.Websocket),
	nextID:   1,
}

type TlsSpecificationsInput struct {
	AlpnProtocols                           []string                  `json:"alpn_protocols,omitempty"`
	SignatureAlgorithms                     []tls.SignatureScheme     `json:"signature_algorithms,omitempty"`
	SupportedVersions                       []uint16                  `json:"supported_versions,omitempty"`
	CertCompressionAlgos                    []tls.CertCompressionAlgo `json:"cert_compression_algos,omitempty"`
	DelegatedCredentialsAlgorithmSignatures []tls.SignatureScheme     `json:"delegated_credentials_algorithm_signatures,omitempty"`
	PSKKeyExchangeModes                     []uint8                   `json:"psk_key_exchange_modes,omitempty"`
	SignatureAlgorithmsCert                 []tls.SignatureScheme     `json:"signature_algorithms_cert,omitempty"`
	ApplicationSettingsProtocols            []string                  `json:"application_settings_protocols,omitempty"`
	RenegotiationSupport                    tls.RenegotiationSupport  `json:"renegotiation_support,omitempty"`
	RecordSizeLimit                         uint16                    `json:"record_size_limit,omitempty"`
}

// Request structure for JSON marshaling/unmarshaling
type RequestData struct {
	Method             string      `json:"method,omitempty"`
	URL                string      `json:"url"`
	Body               interface{} `json:"body,omitempty"`
	BodyB64            string      `json:"body_b64,omitempty"` // Base64 encoded binary body
	Headers            http.Header `json:"headers,omitempty"`
	Proxy              string      `json:"proxy,omitempty"`
	TimeoutMs          int         `json:"timeout_ms,omitempty"`
	ForceHTTP1         bool        `json:"force_http1,omitempty"`
	ForceHTTP3         bool        `json:"force_http3,omitempty"`
	IgnoreBody         bool        `json:"ignore_body,omitempty"`
	NoCookie           bool        `json:"no_cookie,omitempty"`
	DisableRedirects   bool        `json:"disable_redirects,omitempty"`
	MaxRedirects       uint        `json:"max_redirects,omitempty"`
	InsecureSkipVerify bool        `json:"insecure_skip_verify,omitempty"`
}

// SessionConfig structure for JSON marshaling
type SessionConfig struct {
	Browser            string      `json:"browser,omitempty"`
	UserAgent          string      `json:"user_agent,omitempty"`
	Proxy              string      `json:"proxy,omitempty"`
	TimeoutMs          int         `json:"timeout_ms,omitempty"`
	MaxRedirects       uint        `json:"max_redirects,omitempty"`
	ErrOnMaxRedirects  bool        `json:"err_on_max_redirects,omitempty"`
	InsecureSkipVerify bool        `json:"insecure_skip_verify,omitempty"`
	Headers            http.Header `json:"headers,omitempty"`
}

type WebsocketConfig struct {
	URL               string      `json:"url"`
	ReadBufferSize    int         `json:"read_buffer_size,omitempty"`
	WriteBufferSize   int         `json:"write_buffer_size,omitempty"`
	Subprotocols      []string    `json:"subprotocols,omitempty"`
	EnableCompression bool        `json:"enable_compression,omitempty"`
	Headers           http.Header `json:"headers,omitempty"`
}

// Helper function to convert Go string to C string
func goStringToCString(s string) *C.char {
	if s == "" {
		return nil
	}
	return C.CString(s)
}

// Helper function to convert C string to Go string
func cStringToGoString(cs *C.char) string {
	if cs == nil {
		return ""
	}
	return C.GoString(cs)
}

// Helper function to create a C response structure
func createCResponse(resp *azuretls.Response, err error) *C.CFfiResponse {
	cResp := (*C.CFfiResponse)(C.malloc(C.sizeof_CFfiResponse))
	if cResp == nil {
		return nil
	}

	// Initialize all fields to zero/null
	cResp.status_code = 0
	cResp.body = nil
	cResp.body_len = 0
	cResp.headers = nil
	cResp.url = nil
	cResp.error = nil
	cResp.protocol = nil

	if err != nil {
		cResp.error = goStringToCString(err.Error())
		return cResp
	}

	if resp == nil {
		cResp.error = goStringToCString("response is nil")
		return cResp
	}

	cResp.status_code = C.int(resp.StatusCode)

	if resp.Body != nil {
		cResp.body = goStringToCString(string(resp.Body))
		cResp.body_len = C.int(len(resp.Body))
	}

	if resp.Header != nil {
		headerBytes, _ := json.Marshal(resp.Header)
		cResp.headers = goStringToCString(string(headerBytes))
	}

	cResp.url = goStringToCString(resp.Url)

	// Determine protocol from response
	protocol := "HTTP/1.1"
	if resp.HttpResponse != nil {
		if resp.HttpResponse.ProtoMajor == 2 {
			protocol = "HTTP/2"
		} else if resp.HttpResponse.Proto != "" {
			protocol = resp.HttpResponse.Proto
		}
	}

	cResp.protocol = goStringToCString(protocol)

	return cResp
}

// Thread-safe method to get a session
func (sm *SessionManager[T]) getSession(sessionID uintptr) (T, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	session, exists := sm.sessions[sessionID]
	return session, exists
}

// Thread-safe method to add a session
func (sm *SessionManager[T]) addSession(session T) uintptr {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sessionID := sm.nextID
	sm.sessions[sessionID] = session
	sm.nextID++
	return sessionID
}

// Thread-safe method to remove a session
func (sm *SessionManager[T]) removeSession(sessionID uintptr) (T, bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	session, exists := sm.sessions[sessionID]
	if exists {
		delete(sm.sessions, sessionID)
		return session, true
	}
	return session, false
}

// Thread-safe method to close all sessions
func (sm *SessionManager[T]) closeAllSessions() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for id, session := range sm.sessions {
		session.Close()
		delete(sm.sessions, id)
	}
}

//export azuretls_session_new
func azuretls_session_new(configJSON *C.char) uintptr {
	session := azuretls.NewSession()
	if configJSON != nil {
		configStr := cStringToGoString(configJSON)
		var config SessionConfig
		if err := json.Unmarshal([]byte(configStr), &config); err == nil {
			// Apply configuration
			if config.Browser != "" {
				session.Browser = config.Browser
			}
			if config.UserAgent != "" {
				session.UserAgent = config.UserAgent
			}
			if config.Proxy != "" {
				session.SetProxy(config.Proxy)
			}
			if config.TimeoutMs > 0 {
				session.SetTimeout(time.Duration(config.TimeoutMs) * time.Millisecond)
			}
			if config.MaxRedirects > 0 {
				session.MaxRedirects = config.MaxRedirects
			}
			if !config.ErrOnMaxRedirects {
				session.CheckRedirect = func(req *azuretls.Request, reqs []*azuretls.Request) error {
					if uint(len(reqs)) >= req.MaxRedirects {
						return azuretls.ErrUseLastResponse
					}
					return nil
				}
			}
			session.InsecureSkipVerify = config.InsecureSkipVerify

			if len(config.Headers) > 0 {
				session.Header = config.Headers
			}
		}
	}

	sessionID := sessionManager.addSession(session)

	// Prevent session from being garbage collected
	runtime.SetFinalizer(session, nil)

	return sessionID
}

//export azuretls_session_close
func azuretls_session_close(sessionID uintptr) {
	if session, exist := sessionManager.removeSession(sessionID); exist && session != nil {
		session.Close()
	}
}

//export azuretls_session_do
func azuretls_session_do(sessionID uintptr, requestJSON *C.char) *C.CFfiResponse {
	session, exists := sessionManager.getSession(sessionID)
	if !exists {
		return createCResponse(nil, fmt.Errorf("session not found"))
	}

	if requestJSON == nil {
		return createCResponse(nil, fmt.Errorf("request JSON is null"))
	}

	requestStr := cStringToGoString(requestJSON)
	var reqData RequestData
	if err := json.Unmarshal([]byte(requestStr), &reqData); err != nil {
		return createCResponse(nil, fmt.Errorf("failed to parse request JSON: %v", err))
	}

	// Create request
	req := &azuretls.Request{
		Method: reqData.Method,
		Url:    reqData.URL,
		Body:   reqData.Body,
	}

	if reqData.TimeoutMs > 0 {
		req.TimeOut = time.Duration(reqData.TimeoutMs) * time.Millisecond
	}

	req.ForceHTTP1 = reqData.ForceHTTP1
	req.ForceHTTP3 = reqData.ForceHTTP3
	req.IgnoreBody = reqData.IgnoreBody
	req.NoCookie = reqData.NoCookie
	req.DisableRedirects = reqData.DisableRedirects
	req.InsecureSkipVerify = reqData.InsecureSkipVerify

	if reqData.MaxRedirects > 0 {
		req.MaxRedirects = reqData.MaxRedirects
	}

	// Handle headers
	if len(reqData.Headers) > 0 {
		req.Header = reqData.Headers
	} else if len(reqData.Headers) > 0 {
		req.Header = make(map[string][]string)
	}

	// Decode Base64 body if present
	if reqData.BodyB64 != "" {
		bodyBytes, err := base64.StdEncoding.DecodeString(reqData.BodyB64)
		if err == nil {
			req.Body = bodyBytes
		}
	}

	// Execute request
	resp, err := session.Do(req)
	return createCResponse(resp, err)
}

//export azuretls_session_do_bytes
func azuretls_session_do_bytes(sessionID uintptr, method *C.char, url *C.char, headersJSON *C.char, body *C.uchar, bodyLen C.size_t) *C.CFfiResponse {
	session, exists := sessionManager.getSession(sessionID)
	if !exists {
		return createCResponse(nil, fmt.Errorf("session not found"))
	}

	if method == nil || url == nil {
		return createCResponse(nil, fmt.Errorf("method and URL are required"))
	}

	methodStr := cStringToGoString(method)
	urlStr := cStringToGoString(url)

	// Create request
	req := &azuretls.Request{
		Method: methodStr,
		Url:    urlStr,
	}

	// Handle binary body
	if body != nil && bodyLen > 0 {
		// Convert C bytes to Go slice
		bodyBytes := C.GoBytes(unsafe.Pointer(body), C.int(bodyLen))
		req.Body = bodyBytes
	}

	// Parse headers if provided
	if headersJSON != nil {
		headersStr := cStringToGoString(headersJSON)
		var headers map[string]string
		if err := json.Unmarshal([]byte(headersStr), &headers); err == nil {
			req.Header = make(map[string][]string)
			for k, v := range headers {
				req.Header[k] = []string{v}
			}
		}
	}

	// Execute request
	resp, err := session.Do(req)
	return createCResponse(resp, err)
}

//export azuretls_session_apply_ja3
func azuretls_session_apply_ja3(sessionID uintptr, ja3 *C.char, navigator *C.char, tlsSpecifications *C.char) *C.char {
	session, exists := sessionManager.getSession(sessionID)
	if !exists {
		return goStringToCString("session not found")
	}

	ja3Str := cStringToGoString(ja3)
	navStr := cStringToGoString(navigator)
	tlsSpecificationsStr := cStringToGoString(tlsSpecifications)

	if navStr == "" {
		navStr = azuretls.Chrome
	}
	if tlsSpecificationsStr == "" {
		if err := session.ApplyJa3(ja3Str, navStr); err != nil {
			return goStringToCString(err.Error())
		}
	} else {
		var tlsSpecificationsData TlsSpecificationsInput
		if err := json.Unmarshal([]byte(tlsSpecificationsStr), &tlsSpecificationsData); err != nil {
			return goStringToCString(err.Error())
		}

		tlsSpecificationsReal := azuretls.TlsSpecifications{}
		tlsSpecificationsReal.AlpnProtocols = tlsSpecificationsData.AlpnProtocols
		tlsSpecificationsReal.SignatureAlgorithms = tlsSpecificationsData.SignatureAlgorithms
		tlsSpecificationsReal.SupportedVersions = tlsSpecificationsData.SupportedVersions
		tlsSpecificationsReal.CertCompressionAlgos = tlsSpecificationsData.CertCompressionAlgos
		tlsSpecificationsReal.DelegatedCredentialsAlgorithmSignatures = tlsSpecificationsData.DelegatedCredentialsAlgorithmSignatures
		tlsSpecificationsReal.PSKKeyExchangeModes = tlsSpecificationsData.PSKKeyExchangeModes
		tlsSpecificationsReal.SignatureAlgorithmsCert = tlsSpecificationsData.SignatureAlgorithmsCert
		tlsSpecificationsReal.ApplicationSettingsProtocols = tlsSpecificationsData.ApplicationSettingsProtocols
		tlsSpecificationsReal.RenegotiationSupport = tlsSpecificationsData.RenegotiationSupport
		tlsSpecificationsReal.RecordSizeLimit = tlsSpecificationsData.RecordSizeLimit
		if err := session.ApplyJa3WithSpecifications(ja3Str, &tlsSpecificationsReal, navStr); err != nil {
			return goStringToCString(err.Error())
		}
	}

	return nil
}

//export azuretls_session_apply_http2
func azuretls_session_apply_http2(sessionID uintptr, fingerprint *C.char) *C.char {
	session, exists := sessionManager.getSession(sessionID)
	if !exists {
		return goStringToCString("session not found")
	}

	fpStr := cStringToGoString(fingerprint)
	if err := session.ApplyHTTP2(fpStr); err != nil {
		return goStringToCString(err.Error())
	}

	return nil
}

//export azuretls_session_apply_http3
func azuretls_session_apply_http3(sessionID uintptr, fingerprint *C.char) *C.char {
	session, exists := sessionManager.getSession(sessionID)
	if !exists {
		return goStringToCString("session not found")
	}

	fpStr := cStringToGoString(fingerprint)
	if err := session.ApplyHTTP3(fpStr); err != nil {
		return goStringToCString(err.Error())
	}

	return nil
}

//export azuretls_session_set_proxy
func azuretls_session_set_proxy(sessionID uintptr, proxy *C.char) *C.char {
	session, exists := sessionManager.getSession(sessionID)
	if !exists {
		return goStringToCString("session not found")
	}

	proxyStr := cStringToGoString(proxy)
	if err := session.SetProxy(proxyStr); err != nil {
		return goStringToCString(err.Error())
	}

	return nil
}

//export azuretls_session_clear_proxy
func azuretls_session_clear_proxy(sessionID uintptr) {
	session, exists := sessionManager.getSession(sessionID)
	if exists {
		session.ClearProxy()
	}
}

//export azuretls_session_add_pins
func azuretls_session_add_pins(sessionID uintptr, urlStr *C.char, pinsJSON *C.char) *C.char {
	session, exists := sessionManager.getSession(sessionID)
	if !exists {
		return goStringToCString("session not found")
	}

	urlString := cStringToGoString(urlStr)
	pinsString := cStringToGoString(pinsJSON)

	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return goStringToCString(fmt.Sprintf("invalid URL: %v", err))
	}

	var pins []string
	if err := json.Unmarshal([]byte(pinsString), &pins); err != nil {
		return goStringToCString(fmt.Sprintf("failed to parse pins JSON: %v", err))
	}

	if err := session.AddPins(parsedURL, pins); err != nil {
		return goStringToCString(err.Error())
	}

	return nil
}

//export azuretls_session_clear_pins
func azuretls_session_clear_pins(sessionID uintptr, urlStr *C.char) *C.char {
	session, exists := sessionManager.getSession(sessionID)
	if !exists {
		return goStringToCString("session not found")
	}

	urlString := cStringToGoString(urlStr)
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return goStringToCString(fmt.Sprintf("invalid URL: %v", err))
	}

	if err := session.ClearPins(parsedURL); err != nil {
		return goStringToCString(err.Error())
	}

	return nil
}

//export azuretls_session_get_ip
func azuretls_session_get_ip(sessionID uintptr) *C.char {
	session, exists := sessionManager.getSession(sessionID)
	if !exists {
		return goStringToCString("session not found")
	}

	ip, err := session.Ip()
	if err != nil {
		return goStringToCString(fmt.Sprintf("error: %v", err))
	}

	return goStringToCString(ip)
}

//export azuretls_session_get_cookies
func azuretls_session_get_cookies(sessionID uintptr, urlStr *C.char) *C.char {
	session, exists := sessionManager.getSession(sessionID)
	if !exists {
		return goStringToCString("error: session not found")
	}

	if session.CookieJar == nil {
		return goStringToCString("[]")
	}

	urlString := cStringToGoString(urlStr)
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return goStringToCString(fmt.Sprintf("error: invalid URL: %v", err))
	}

	cookies := session.CookieJar.Cookies(parsedURL)

	// Convert cookies to a JSON array
	type CookieInfo struct {
		Name     string `json:"name"`
		Value    string `json:"value"`
		Path     string `json:"path,omitempty"`
		Domain   string `json:"domain,omitempty"`
		Expires  string `json:"expires,omitempty"`
		Secure   bool   `json:"secure,omitempty"`
		HttpOnly bool   `json:"http_only,omitempty"`
		SameSite string `json:"same_site,omitempty"`
	}

	cookieList := make([]CookieInfo, 0, len(cookies))
	for _, cookie := range cookies {
		sameSite := ""
		switch cookie.SameSite {
		case 1:
			sameSite = "Lax"
		case 2:
			sameSite = "Strict"
		case 3:
			sameSite = "None"
		}

		cookieInfo := CookieInfo{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Path:     cookie.Path,
			Domain:   cookie.Domain,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HttpOnly,
			SameSite: sameSite,
		}

		if !cookie.Expires.IsZero() {
			cookieInfo.Expires = cookie.Expires.Format(time.RFC3339)
		}

		cookieList = append(cookieList, cookieInfo)
	}

	cookiesJSON, err := json.Marshal(cookieList)
	if err != nil {
		return goStringToCString(fmt.Sprintf("error: failed to marshal cookies: %v", err))
	}

	return goStringToCString(string(cookiesJSON))
}

//export azuretls_session_new_websocket
func azuretls_session_new_websocket(sessionId uintptr, config *C.char, outWsSessionId *uintptr) *C.char {
	session, exists := sessionManager.getSession(sessionId)
	if !exists {
		return goStringToCString("session not found")
	}
	var wsConfig WebsocketConfig
	err := json.Unmarshal([]byte(cStringToGoString(config)), &wsConfig)
	if err != nil {
		return goStringToCString(err.Error())
	}
	ws, err := session.NewWebsocket(
		wsConfig.URL,
		wsConfig.ReadBufferSize,
		wsConfig.WriteBufferSize,
		wsConfig.Subprotocols,
		wsConfig.EnableCompression,
		wsConfig.Headers,
	)
	if err != nil {
		return goStringToCString(err.Error())
	}
	if ws == nil {
		return goStringToCString("ws is nil")
	}

	*outWsSessionId = websocketSessionManager.addSession(ws)

	// Prevent session from being garbage collected
	runtime.SetFinalizer(ws, nil)

	return nil
}

//export azuretls_websocket_close
func azuretls_websocket_close(sessionID uintptr) {
	if session, exist := websocketSessionManager.removeSession(sessionID); exist && session != nil {
		session.Close()
	}
}

//export azuretls_websocket_read_message
func azuretls_websocket_read_message(sessionID uintptr, outMessageType *int, output **C.char, length *int) *C.char {
	*output = nil
	*length = 0
	ws, exists := websocketSessionManager.getSession(sessionID)
	if !exists || ws == nil {
		return goStringToCString("session not found")
	}
	messageType, message, err := ws.ReadMessage()
	if err != nil {
		return goStringToCString(err.Error())
	}
	*outMessageType = messageType
	*output = (*C.char)(C.CBytes(message))
	*length = len(message)
	return nil
}

//export azuretls_websocket_write_message
func azuretls_websocket_write_message(sessionID uintptr, messageType int, message *C.char, length int) *C.char {
	ws, exists := websocketSessionManager.getSession(sessionID)
	if !exists || ws == nil {
		return goStringToCString("session not found")
	}

	messageGo := C.GoBytes(unsafe.Pointer(message), C.int(length))
	if err := ws.WriteMessage(messageType, messageGo); err != nil {
		return goStringToCString(err.Error())
	}

	return nil
}

//export azuretls_free_string
func azuretls_free_string(str *C.char) {
	if str != nil {
		C.free(unsafe.Pointer(str))
	}
}

//export azuretls_free_response
func azuretls_free_response(resp *C.CFfiResponse) {
	if resp != nil {
		if resp.body != nil {
			C.free(unsafe.Pointer(resp.body))
		}
		if resp.headers != nil {
			C.free(unsafe.Pointer(resp.headers))
		}
		if resp.url != nil {
			C.free(unsafe.Pointer(resp.url))
		}
		if resp.error != nil {
			C.free(unsafe.Pointer(resp.error))
		}
		if resp.protocol != nil {
			C.free(unsafe.Pointer(resp.protocol))
		}
		C.free(unsafe.Pointer(resp))
	}
}

//export azuretls_version
func azuretls_version() *C.char {
	return goStringToCString(Version)
}

//export azuretls_init
func azuretls_init() {
	// Initialize the library if needed
}

//export azuretls_cleanup
func azuretls_cleanup() {
	// Close all active sessions using thread-safe method
	sessionManager.closeAllSessions()
}

func main() {
	// Required for building as shared library
}
