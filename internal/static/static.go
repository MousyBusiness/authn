package static

import (
	"github.com/pkg/errors"
	"os/exec"
	"runtime"
	"strings"
)

const successHTML = `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>__TITLE__</title>

    <style media="screen">
      body { background: #ECEFF1; color: rgba(0,0,0,0.87); font-family: Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 0; }
      #message { background: white; max-width: 360px; margin: 100px auto 16px; padding: 32px 24px 8px; border-radius: 3px; }
      #message h1 { color: #01A2C8; font-weight: bold; font-size: 24px; margin: 0 0 16px; }
      #message h2 { font-size: 16px; font-weight: 300; color: rgba(0,0,0,0.6); margin: 0 0 16px;}
      #message p { line-height: 140%; margin: 16px 0 24px; font-size: 14px; }
      #message a { display: block; text-align: center; background: #039be5; text-transform: uppercase; text-decoration: none; color: white; padding: 16px; border-radius: 4px; }
      #message, #message a { box-shadow: 0 1px 3px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.24); }
      #load { color: rgba(0,0,0,0.4); text-align: center; font-size: 13px; }
      @media (max-width: 600px) {
        body, #message { margin-top: 0; background: white; box-shadow: none; }
        body { border-top: 16px solid #4caf50; }
      }

      code { font-size: 18px; color: #999; }
    </style>
  </head>
  <body>
    <div id="message">
      <h1>__TITLE__</h1>
      <h2>Login Successful</h2>
      <p>You can now return to __TITLE__.</p>
    </div>
  </body>
</html>`

func SuccessHTML(title string) string {
	return strings.Replace(successHTML, "__TITLE__", title, -1)
}

const failedHTML = `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>__TITLE__</title>

    <style media="screen">
      body { background: #ECEFF1; color: rgba(0,0,0,0.87); font-family: Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 0; }
      #message { background: white; max-width: 360px; margin: 100px auto 16px; padding: 32px 24px 8px; border-radius: 3px; }
      #message h1 { color: #FF8915; font-weight: bold; font-size: 24px; margin: 0 0 16px; }
      #message h2 { font-size: 16px; font-weight: 300; color: rgba(0,0,0,0.6); margin: 0 0 16px;}
      #message p { line-height: 140%; margin: 16px 0 24px; font-size: 14px; }
      #message a { display: block; text-align: center; background: #039be5; text-transform: uppercase; text-decoration: none; color: white; padding: 16px; border-radius: 4px; }
      #message, #message a { box-shadow: 0 1px 3px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.24); }
      #load { color: rgba(0,0,0,0.4); text-align: center; font-size: 13px; }
      @media (max-width: 600px) {
        body, #message { margin-top: 0; background: white; box-shadow: none; }
        body { border-top: 16px solid #4caf50; }
      }

      code { font-size: 18px; color: #999; }
    </style>
  </head>
  <body>
    <div id="message">
      <h1>__TITLE__</h1>
      <h2>Login Failed</h2>
      <p>Something went wrong.</p>
    </div>
  </body>
</html>`

func FailedHTML(title string) string {
	return strings.Replace(failedHTML, "__TITLE__", title, -1)
}

// Open attempts an os specific opening of transferred files or urls
func Open(uri string) error {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", uri).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll.FileProtocolHandler", uri).Start()
	case "darwin":
		err = exec.Command("open", uri).Start()
	default:
		err = errors.New("unsupported platform, cannot open browser")
	}

	return err
}

func IsDesktop() bool {
	switch runtime.GOOS {
	case "linux":
		return true
	case "windows":
		return true
	case "darwin":
		return true
	}

	return false
}
