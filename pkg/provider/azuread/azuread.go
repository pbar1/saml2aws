package azuread

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/provider"
)

var logger = logrus.WithField("provider", "azuread")

// Client interface for handling the Azure AD connection
type Client struct {
	client *provider.HTTPClient
	idpAccount *cfg.IDPAccount
	authSubmitURL string
	samlAssertion string
}

// New Azure AD client connection
func New(idpAccount *cfg.IDPAccount) (*Client, error) {
	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: idpAccount.SkipVerify, Renegotiation: tls.RenegotiateFreelyAsClient},
	}

	client, err := provider.NewHTTPClient(tr)
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}

	return &Client{
		client:     client,
		idpAccount: idpAccount,
	}, nil
}

// Authenticate Authenticate to Azure AD and return the data from the body of the SAML assertion.
func (ac *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	authForm := url.Values{}

	var authSubmitURL string
	var samlAssertion string

	// var baseURL = "https://account.activedirectory.windowsazure.com"
	var applicationID = ""
	var tenantID = ""

	azureADURL := fmt.Sprintf("%s/applications/redirecttofederatedapplication.aspx?Operation=SignIn&applicationId=%s&tenantId=%s", loginDetails.URL, applicationID, tenantID)

	logger.WithField("url", azureADURL).Debug("GET")

	res, err := ac.client.Get(azureADURL)
	if err != nil {
		return "", errors.Wrap(err, "error retieving form")
	}

	log.Printf("Type of res: %T", res)

	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return "", errors.Wrap(err, "failed to build document from response")
	}

	log.Printf("Type of doc: %T", doc)
	log.Printf("%s", doc)

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		updateLoginFormData(authForm, s, loginDetails)
	})

	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, ok := s.Attr("action")
		if !ok {
			return
		}
		authSubmitURL = action
	})

	if authSubmitURL == "" {
		return "", fmt.Errorf("unable to locate IDP authentication form submit URL")
	}

	authSubmitURL = fmt.Sprintf("%s%s", loginDetails.URL, ac.authSubmitURL)

	log.Printf("id authentication url: %s", authSubmitURL)

	return samlAssertion, nil
}

func updateLoginFormData(authForm url.Values, s *goquery.Selection, user *creds.LoginDetails) {
	return
}

func extractFormData(res *http.Response) (url.Values, string, error) {
	return nil, "", nil
}
