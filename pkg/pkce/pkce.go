package pkce

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/mousybusiness/authn/internal/errs"
	"github.com/mousybusiness/authn/internal/rstr"
	"github.com/mousybusiness/authn/internal/static"
	"github.com/mousybusiness/authn/pkg/creds"
	"github.com/mousybusiness/go-web/web"
	cv "github.com/nirasan/go-oauth-pkce-code-verifier"
	"github.com/okta/okta-jwt-verifier-golang"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

type pkceFlow struct {
	config       Config
	credentials  *creds.Credentials
	codeVerifier *cv.CodeVerifier
	server       *http.Server
	authWG       *sync.WaitGroup
	nonce        string
	state        string
}

const (
	defaultPort = "63353"
	defaultRedirectPath = "/login/callback"
)

var (
	//https://oauth.net/2/scope/
	scopes = []string{
		"email",
		"profile",
		"openid",
		"offline_access",
	}
)

type Config struct {
	// Title for redirect website
	// e.g. GooseClip
	Title string
	// Port for localhosted redirect server if used
	// default 63353
	Port  string

	ClientID string
	Issuer   string // e.g. "https://oie-1234567.oktapreview.com/oauth2/default"
	AuthURL  string // e.g. "https://oie-1234567.oktapreview.com/oauth2/default/v1/authorize"
	TokenURL string // e.g. "https://oie-1234567.oktapreview.com/oauth2/default/v1/token"

	RedirectURL  string // e.g. "http://localhost:63353/login/callback"
	redirectPath string // generated from RedirectURL
}

func New(config Config) (*pkceFlow, error) {
	if config.Title == "" {
		return nil, errors.New("require Title")
	}

	if config.ClientID == "" {
		return nil, errors.New("require ClientID")
	}

	if config.Issuer == "" {
		return nil, errors.New("require AuthURL")
	}

	if config.AuthURL == "" {
		return nil, errors.New("require AuthURL")
	}

	if config.TokenURL == "" {
		return nil, errors.New("require TokenURL")
	}

	if config.Port == "" {
		config.Port = defaultPort
	}

	if config.RedirectURL == "" {
		config.RedirectURL = fmt.Sprintf("http://localhost:%v%v", config.Port, defaultRedirectPath)
		log.Warn("default redirection URL is unencrypted")
	}

	re  := regexp.MustCompile(`^https?://[\w-.]+(/.+)$`)
	if !re.MatchString(config.RedirectURL) {
		return nil, errors.New("invalid redirect url")
	}
	hits := re.FindAllStringSubmatch(config.RedirectURL, 1)
	if len(hits) == 0 || len(hits[0]) != 2 {
		return nil, errors.New("failed to extract redirect path from RedirectURL")
	}
	config.redirectPath = hits[0][1]

	flow := &pkceFlow{}
	flow.credentials = &creds.Credentials{}
	callback = flow.redirectHandler
	flow.nonce = rstr.RandomString(8)
	flow.state = rstr.RandomString(16)
	return flow, nil
}

// Auth implements the PKCE OAuth2 flow.
func (p *pkceFlow) Auth() *creds.Credentials {
	p.codeVerifier, _ = cv.CreateCodeVerifier()
	codeChallenge := p.codeVerifier.CodeChallengeS256()

	p.authWG = new(sync.WaitGroup)
	p.authWG.Add(1)
	p.serve()

	s := strings.Join(scopes, " ")
	params := url.Values{}
	//params.Add("idp", p.idp) // TODO IDP
	params.Add("client_id", p.config.ClientID)
	params.Add("response_type", "code")
	//params.Add("response_mode", "query") // TODO IDP
	params.Add("scope", s)
	params.Add("code_challenge", codeChallenge)
	params.Add("code_challenge_method", "S256")
	params.Add("redirect_uri", p.config.RedirectURL)
	params.Add("state", p.state)
	params.Add("nonce", p.nonce)
	uri := p.config.AuthURL + "?" + params.Encode()

	if static.IsDesktop() {
		if err := static.Open(uri); err != nil {
			fmt.Println("Couldn't open browser, please visit manually")
		}
	}

	fmt.Printf("Visit the URL for the auth dialog: %v\n", uri)

	p.authWG.Wait()
	time.Sleep(time.Second)
	if err := p.server.Shutdown(context.TODO()); err != nil {
		log.Error(errors.Wrap(err, "error while shutting down server"))
	}

	return p.credentials
}

func (p *pkceFlow) Refresh(refreshToken creds.RefreshToken) (*creds.Credentials, error) {
	params := url.Values{}
	params.Add("grant_type", "refresh_token")
	params.Add("refresh_token", string(refreshToken))
	params.Add("client_id", p.config.ClientID)
	params.Add("scope", strings.Join(scopes, " "))
	params.Add("redirect_uri", p.config.RedirectURL)

	b := []byte(params.Encode())
	code, body, err := web.Post(p.config.TokenURL, time.Second*60, b,
		web.KV{Key: "Accept", Value: "application/json"},
		web.KV{Key: "Content-Type", Value: "application/x-www-form-urlencoded"},
		web.KV{Key: "Cache-Control", Value: "no-cache"},
	)
	if err != nil {
		return nil, err
	}

	if code != http.StatusOK {
		return nil, errs.NewHttpError(code, body, "error response from token exchange")
	}

	// process the response
	var responseData map[string]interface{}

	// unmarshal the json into a string map
	err = json.Unmarshal(body, &responseData)
	if err != nil {
		return nil, err
	}

	accessToken, idToken, ref, expiresIn, err := p.extractFromResponse(responseData)
	if err != nil {
		return nil, err
	}

	uid, err := p.verifyJWT(idToken)
	if err != nil {
		return nil, err
	}

	p.credentials.Expiry = time.Now().Add(time.Duration(expiresIn-60) * time.Second) // allow 1 minute of buffer
	p.credentials.AccessToken = accessToken
	p.credentials.IDToken = idToken
	p.credentials.RefreshToken = ref
	p.credentials.UID = uid

	log.Debugf("refresh successful!")

	return p.credentials, nil
}

// exchangeCode trades the authorization code retrieved from the first OAuth2 leg for a token
func (p *pkceFlow) exchangeCode(authorizationCode string, callbackURL string) (creds.AccessToken, creds.IDToken, creds.RefreshToken, float64, error) {
	// set the url and form-encoded data for the POST to the access token endpoint
	url := p.config.TokenURL
	codeVerifier := p.codeVerifier.String()
	data := fmt.Sprintf(
		"grant_type=authorization_code"+
			"&client_id=%s"+
			"&code_verifier=%s"+
			"&code=%s"+
			"&redirect_uri=%s",
		p.config.ClientID, codeVerifier, authorizationCode, callbackURL)

	b := []byte(data)
	code, body, err := web.Post(url, time.Second*60, b,
		web.KV{Key: "Accept", Value: "application/json"},
		web.KV{Key: "Content-Type", Value: "application/x-www-form-urlencoded"},
		web.KV{Key: "Cache-Control", Value: "no-cache"},
	)
	if err != nil {
		return "", "", "", 0, err
	}

	if code != http.StatusOK {
		return "", "", "", 0, errs.NewHttpError(code, body, "error response from token exchange")
	}

	// process the response
	var responseData map[string]interface{}

	// unmarshal the json into a string map
	err = json.Unmarshal(body, &responseData)
	if err != nil {
		return "", "", "", 0, err
	}

	return p.extractFromResponse(responseData)
}

func (p *pkceFlow) extractFromResponse(responseData map[string]interface{}) (creds.AccessToken, creds.IDToken, creds.RefreshToken, float64, error) {

	var accessToken string
	var idToken string
	var refreshToken string
	var expiresIn float64

	if acc, ok := responseData["access_token"].(string); ok {
		accessToken = acc
	}

	if idt, ok := responseData["id_token"].(string); ok {
		idToken = idt
	}

	if rft, ok := responseData["refresh_token"].(string); ok {
		refreshToken = rft
	}

	if ei, ok := responseData["expires_in"].(float64); ok {
		expiresIn = ei
	}

	if idToken != "" && refreshToken != "" && expiresIn != 0 {
		return creds.AccessToken(accessToken), creds.IDToken(idToken), creds.RefreshToken(refreshToken), expiresIn, nil
	}

	return "", "", "", 0, fmt.Errorf("unable to get data from response, accessToken: %v, idToken: %v, refreshToken: %v, expiresIn: %v", accessToken != "", idToken != "", refreshToken != "", expiresIn != 0)
}

// TODO allow custom verify here
// TODO verify nonce claim
func (p *pkceFlow) verifyJWT(token creds.IDToken) (string, error) {
	toValidate := map[string]string{}
	toValidate["aud"] = p.config.ClientID
	toValidate["cid"] = p.config.ClientID

	verifier := jwtverifier.JwtVerifier{
		Issuer:           p.config.Issuer,
		ClaimsToValidate: toValidate,
	}

	jwt, err := verifier.New().VerifyIdToken(string(token))
	if err != nil {
		return "", err
	}
	log.Infof("JWT: %v", jwt.Claims)

	if si, ok := jwt.Claims["sub"]; ok {
		if uid, ok := si.(string); ok {
			return uid, nil
		}
	}
	return "", errors.New("couldn't extract uid")
}

var callback func(w http.ResponseWriter, r *http.Request)

func handlerWrapper(w http.ResponseWriter, r *http.Request) {
	if callback != nil {
		callback(w, r)
	}
}

func (p *pkceFlow) serve() {
	if p.server != nil {
		_ = p.server.Close()
	}

	// use server so we can shutdown loter
	server := &http.Server{
		Addr: ":" + defaultPort,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(p.config.redirectPath, handlerWrapper)
	server.Handler = mux

	go func() {
		if err := server.ListenAndServe(); err != nil {
			if !strings.HasSuffix(err.Error(), "Server closed") {
				log.Error(errors.Wrap(err, "failed to listen and serve login callback"))
				return
			}
		}
	}()

	p.server = server
}

func (p *pkceFlow) redirectHandler(w http.ResponseWriter, r *http.Request) {

	defer p.authWG.Done() // TODO this will leak if callback isn't hit

	// get the authorization code
	code := r.URL.Query().Get("code")
	if code == "" {
		log.Error("code not in callback")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, static.FailedHTML(p.config.Title))
		p.fail()
		return
	}

	// trade the authorization code and the code verifier for an access token
	accessToken, idToken, refreshToken, expiresIn, err := p.exchangeCode(code, p.config.RedirectURL)
	if err != nil {
		log.Errorf("failed to get token, err: %v", err)
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, static.FailedHTML(p.config.Title))
		p.fail()
		return
	}

	uid, err := p.verifyJWT(idToken)
	if err != nil {
		log.Error("failed to get uid from JWT")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, static.FailedHTML(p.config.Title))
		p.fail()
		return
	}

	// assign the idToken globally so it can be returned by Auth
	p.credentials.Expiry = time.Now().Add(time.Duration(expiresIn-60) * time.Second) // allow 1 minute of buffer
	p.credentials.UID = uid
	p.credentials.AccessToken = accessToken
	p.credentials.IDToken = idToken
	p.credentials.RefreshToken = refreshToken

	// display success HTML
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintln(w, static.SuccessHTML(p.config.Title))

	log.Infof("logged in")
}

// fail closes the HTTP server
func (p *pkceFlow) fail() {
	go func() {
		err := p.server.Close()
		if err != nil {
			log.Error(err)
		}
	}()
}
