package skas

import (
	"context"
	"fmt"
	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
	"skas/sk-common/pkg/skclient"
	"skas/sk-common/proto/v1/proto"
	"strconv"
)

//var _ server.ConnectorConfig = &Config{}		// Will trigger import cycle loop

type Config struct {
	LoginPrompt   string          `json:"loginPrompt"`
	LoginProvider skclient.Config `json:"loginProvider"`
}

func (c Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	logger.Infof("SKAS connector Open(id=%s, url=%s, clientId=%s)", id, c.LoginProvider.Url, c.LoginProvider.ClientAuth.Id)
	loginClient, err := skclient.New(&c.LoginProvider, "", "")
	if err != nil {
		return nil, fmt.Errorf("error on configuring login provider: %w", err)
	}
	cnct := skasConnector{
		id:          id,
		loginClient: loginClient,
		prompt:      c.LoginPrompt,
		logger:      logger,
	}
	return cnct, nil
}

var _ connector.PasswordConnector = &skasConnector{}

type skasConnector struct {
	id          string
	prompt      string
	loginClient skclient.SkClient
	logger      log.Logger
}

func (sc skasConnector) Prompt() string {
	if sc.prompt != "" {
		return sc.prompt
	} else {
		return "SKAS login"
	}
}

func (sc skasConnector) Login(ctx context.Context, scope connector.Scopes, username, password string) (identity connector.Identity, validPassword bool, err error) {
	lr := &proto.LoginRequest{
		Login:      username,
		Password:   password,
		ClientAuth: sc.loginClient.GetClientAuth(),
	}
	loginResponse := &proto.LoginResponse{}
	err = sc.loginClient.Do(proto.LoginMeta, lr, loginResponse, nil)
	if err != nil {
		return connector.Identity{}, false, fmt.Errorf("error on exchange on %s: %w", proto.LoginMeta.UrlPath, err) // Do() return a documented message
	}
	if loginResponse.Success {
		ident := connector.Identity{
			UserID:   strconv.Itoa(loginResponse.Uid),
			Username: loginResponse.Login,
			Groups:   loginResponse.Groups,
		}
		if len(loginResponse.CommonNames) > 0 {
			ident.PreferredUsername = loginResponse.CommonNames[0]
		}
		if len(loginResponse.Emails) > 0 {
			ident.Email = loginResponse.Emails[0]
		}
		sc.logger.Infof("connector:%s: login of '%s' successful. => preferredUserName:'%s'  email:'%s'  groups:'%v'", sc.id, ident.Username, ident.PreferredUsername, ident.Email, ident.Groups)
		return ident, true, nil
	} else {
		sc.logger.Infof("connector:%s: login of '%s' failed", sc.id, username)
		return connector.Identity{}, false, nil
	}
}
