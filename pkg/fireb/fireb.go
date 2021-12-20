package fireb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/mousybusiness/authn/internal/rstr"
	"github.com/mousybusiness/authn/internal/static"
	"github.com/mousybusiness/authn/pkg/creds"
	"github.com/mousybusiness/go-web/web"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultPort         = "63353"
	refreshURL          = "https://securetoken.googleapis.com/v1/token"
	authURL             = "https://accounts.google.com/o/oauth2/auth"
	tokenURL            = "https://accounts.google.com/o/oauth2/token"
	idpURL              = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp"
	defaultRedirectPath = "/__/auth/handler"
)

var (
	scopes = []string{
		"email",
		"profile",
		"openid",
		"https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/userinfo.profile",
	}

	nonce  = rstr.RandomString(12)
	authWG *sync.WaitGroup
)

type (
	firebaseFlow struct {
		config      Config
		credentials *creds.Credentials
		server      *http.Server
	}

	APIKey string

	Exchange struct {
		Code         string `json:"code"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RedirectURI  string `json:"redirect_uri"`
		GrantType    string `json:"grant_type"`
	}

	Token struct {
		IDToken      string `json:"id_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
		ExpiresIn    int    `json:"expires_in"`
	}

	LoginRequest struct {
		RequestUri          string `json:"requestUri"`
		PostBody            string `json:"postBody"`
		ReturnSecureToken   bool   `json:"returnSecureToken"`
		ReturnIdpCredential bool   `json:"returnIdpCredential"`
	}

	RefreshResponse struct {
		ExpiresIn    string `json:"expires_in"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		UserID       string `json:"user_id"`
		ProjectID    string `json:"project_id"`
	}

	Config struct {
		// Title for redirect website
		// e.g. GooseClip
		Title string
		// Port for localhosted redirect server if used
		// default 63353
		Port string

		// Firebase ClientID found at https://console.cloud.google.com/apis/credentials under 'OAuth 2.0 Clients IDs'
		// e.g. "1234567890-alksjhdflk9a801tbfk3g2e3lj34ne.apps.googleusercontent.com"
		ClientID string
		// Firebase ClientSecret found at https://console.cloud.google.com/apis/credentials under 'OAuth 2.0 Clients IDs'
		// e.g. "abcdeBsNJMUa2I1MYwdrxyz"
		ClientSecret string
		// Firebase APIKey found at https://console.firebase.google.com/u/0/project/YOUR_PROJECT_HERE/settings/general/
		// e.g. "AIzaZyDMMlZyyzjl2x6gX6kh-s6_sJ6zZyb6Vgg",
		APIKey string

		// RedirectURL must be in 'Authorized redirect URIs' at https://console.cloud.google.com/apis/credentials under 'OAuth 2.0 Clients IDs'
		// e.g. "http://localhost:63353/__/auth/handler"
		RedirectURL  string
		redirectPath string // generated from RedirectURL
	}

	CallbackFn func(w http.ResponseWriter, r *http.Request)
)

func New(config Config) (*firebaseFlow, error) {
	if config.Title == "" {
		return nil, errors.New("require Title")
	}

	if config.ClientID == "" {
		return nil, errors.New("require ClientID")
	}

	if config.ClientSecret == "" {
		return nil, errors.New("require ClientSecret")
	}

	if config.APIKey == "" {
		return nil, errors.New("require APIKey")
	}

	if config.Port == "" {
		config.Port = defaultPort
	}

	if config.RedirectURL == "" {
		config.RedirectURL = fmt.Sprintf("http://localhost:%v%v", config.Port, defaultRedirectPath)
		log.Warn("default redirection URL is unencrypted")
	}

	re := regexp.MustCompile(`^https?://[\w-.]+(/.+)$`)
	if !re.MatchString(config.RedirectURL) {
		return nil, errors.New("invalid redirect url")
	}
	hits := re.FindAllStringSubmatch(config.RedirectURL, 1)
	if len(hits) == 0 || len(hits[0]) != 2 {
		return nil, errors.New("failed to extract redirect path from RedirectURL")
	}
	config.redirectPath = hits[0][1]

	flow := &firebaseFlow{
		config: config,
	}
	callback = flow.redirectHandler
	return flow, nil
}

func RefreshFirebaseToken(token creds.RefreshToken, secret APIKey) (RefreshResponse, error) {
	b, err := json.Marshal(struct {
		RefreshToken string `json:"refresh_token"`
		GrantType    string `json:"grant_type"`
	}{
		RefreshToken: string(token),
		GrantType:    "refresh_token",
	})
	if err != nil {
		return RefreshResponse{}, err
	}

	resp, err := http.Post(fmt.Sprintf("%s?key=%s", refreshURL, secret), http.DetectContentType(b), bytes.NewReader(b))
	if err != nil {
		return RefreshResponse{}, err
	}

	code := resp.StatusCode
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return RefreshResponse{}, err
	}

	if code != 200 {
		return RefreshResponse{}, errors.New(fmt.Sprintf("status code not 200, code: %d, error: %v", code, string(body)))
	}

	var r RefreshResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return RefreshResponse{}, err
	}

	return r, nil
}

// Auth generates a URL which the user can click to navigate to the
// Google login page to authenticate their CLI API calls using a Firebase user
func (f *firebaseFlow) Auth(urlCh chan string) *creds.Credentials {
	f.credentials = nil

	authWG = new(sync.WaitGroup)
	authWG.Add(1)

	f.serve()

	s := strings.Join(scopes, " ")

	params := url.Values{}
	params.Add("client_id", f.config.ClientID)
	params.Add("scope", s)
	params.Add("response_type", "code")
	params.Add("state", nonce)
	params.Add("redirect_uri", f.config.RedirectURL)
	params.Add("access_type", "offline")

	uri := authURL + "?" + params.Encode()

	if urlCh != nil {
		urlCh <- uri
	}

	if static.IsDesktop() {
		if err := static.Open(uri); err != nil {
			fmt.Println("couldnt open browser, please visit manually")
		}
	}

	fmt.Printf("Visit the URL for the auth dialog: %v\n", uri)

	authWG.Wait()
	time.Sleep(time.Second)
	if err := f.server.Shutdown(context.TODO()); err != nil {
		log.Error(errors.Wrap(err, "error while shutting down server"))
	}

	return f.credentials
}

func (f *firebaseFlow) Refresh(refreshToken creds.RefreshToken) (*creds.Credentials, error) {
	token, err := RefreshFirebaseToken(refreshToken, APIKey(f.config.APIKey))
	if err != nil {
		return nil, errors.Wrap(err, "require auth token")
	}

	if token.IDToken == "" {
		return nil, errors.New("require auth token: refresh token response invalid")
	}

	// assign the idToken globally so it can be returned by Auth
	if sec, err := strconv.Atoi(token.ExpiresIn); err == nil {
		f.credentials.Expiry = time.Now().Add(time.Duration(sec-60) * time.Second) // allow 1 minute of buffer
	}

	//f.credentials.UID = viper.GetString(config.UIDKey) // TODO
	f.credentials.RefreshToken = refreshToken
	f.credentials.IDToken = creds.IDToken(token.IDToken)

	return f.credentials, nil
}

var callback CallbackFn

func handlerWrapper(w http.ResponseWriter, r *http.Request) {
	if callback != nil {
		callback(w, r)
	}
}

func (f *firebaseFlow) serve() {
	if f.server != nil {
		_ = f.server.Close()
	}

	// use server so we can shutdown loter
	server := &http.Server{
		Addr: ":" + f.config.Port,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(f.config.redirectPath, handlerWrapper)
	f.server.Handler = mux

	go func() {
		if err := server.ListenAndServe(); err != nil {
			if !strings.HasSuffix(err.Error(), "Server closed") {
				log.Error(errors.Wrap(err, "failed to listen and serve login callback"))
				return
			}
		}
	}()

	f.server = server
}

func (f *firebaseFlow) redirectHandler(w http.ResponseWriter, req *http.Request) {
	// inform Auth function that we can return
	defer authWG.Done() // TODO if the callback is never hit this will lock here

	log.Debugf("redirect invoked")
	m := req.URL.Query()
	state := m.Get("state")
	code := m.Get("code")

	if state != nonce {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	ex := Exchange{
		Code:         code,
		ClientID:     f.config.ClientID,
		ClientSecret: f.config.ClientSecret,
		RedirectURI:  f.config.RedirectURL,
		GrantType:    "authorization_code",
	}

	b, err := json.Marshal(ex)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, static.FailedHTML(f.config.Title))
	}

	// exchange auth code for token
	statusCode, body, err := web.Post(tokenURL, time.Second*10, b)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, static.FailedHTML(f.config.Title))
		return
	}

	if statusCode != http.StatusOK {
		w.WriteHeader(statusCode)
		_, _ = fmt.Fprintln(w, "failed to exchange code for token")
		return
	}

	var token Token
	if err := json.Unmarshal(body, &token); err != nil {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, static.FailedHTML(f.config.Title))
		return
	}

	// after the Google OAuth2 token has been received, we need to log into Firebase
	r := LoginRequest{
		RequestUri:          "http://localhost",
		PostBody:            fmt.Sprintf("id_token=%v&providerId=google.com", token.IDToken),
		ReturnSecureToken:   true,
		ReturnIdpCredential: true,
	}

	b, err = json.Marshal(r)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, static.FailedHTML(f.config.Title))
	}

	statusCode, body, err = web.Post(idpURL+"?key="+f.config.APIKey, time.Second*10, b)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, static.FailedHTML(f.config.Title))
		return
	}
	if statusCode != 200 {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, static.FailedHTML(f.config.Title))
		return
	}

	var resp GoogleAuthResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, static.FailedHTML(f.config.Title))
		return
	}

	f.credentials = &creds.Credentials{
		UID:          resp.LocalId,
		IDToken:      creds.IDToken(resp.IDToken),
		RefreshToken: creds.RefreshToken(resp.RefreshToken),
		Expiry:       time.Now(),
	}
	// assign the idToken globally so it can be returned by Auth
	if sec, err := strconv.Atoi(resp.ExpiresIn); err == nil {
		log.Debugf("expires in seconds: %v", sec)
		f.credentials.Expiry = time.Now().Add(time.Duration(sec-60) * time.Second) // allow 1 minute of buffer
	}

	// display success HTML
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintln(w, static.SuccessHTML(f.config.Title))

}
