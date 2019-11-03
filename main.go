// Copyright (c) Derek Author(s) 2017. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/google/go-github/github"

	"github.com/alexellis/derek/auth"
	"github.com/alexellis/derek/config"

	"github.com/alexellis/derek/handler"

	"github.com/alexellis/derek/types"
	"github.com/alexellis/hmac"
)

const (
	dcoCheck              = "dco_check"
	comments              = "comments"
	deleted               = "deleted"
	prDescriptionRequired = "pr_description_required"
	hacktoberfest         = "hacktoberfest"
	releaseNotes          = "release_notes"
)

func main() {
	validateHmac := hmacValidation()

	requestRaw, _ := ioutil.ReadAll(os.Stdin)

	xHubSignature := os.Getenv("Http_X_Hub_Signature")

	if validateHmac && len(xHubSignature) == 0 {
		os.Stderr.Write([]byte("must provide X_Hub_Signature"))
		os.Exit(1)
	}

	config, configErr := config.NewConfig()
	if configErr != nil {
		os.Stderr.Write([]byte(configErr.Error()))
		os.Exit(1)
	}

	if validateHmac {
		err := hmac.Validate(requestRaw, xHubSignature, config.SecretKey)
		if err != nil {
			os.Stderr.Write([]byte(err.Error()))
			os.Exit(1)
		}
	}

	// this is equivalent to github.WebHookType(r)
	eventType := os.Getenv("Http_X_Github_Event")

	if err := handleEvent(eventType, requestRaw, config); err != nil {
		os.Stderr.Write([]byte(err.Error()))
		os.Exit(1)
	}
}

func handleEvent(eventType string, bytesIn []byte, config config.Config) error {
	// event will be a specific github activity event
	event, err := github.ParseWebHook(eventType, bytesIn)
	if err != nil {
		return fmt.Errorf("Cannot parse input %s", err.Error())
	}

	derekConfig, err := getConfig(eventType, event, config)
	if err != nil {
		return err
	}

	switch eventType {
	case "release":
		req, ok := event.(*github.ReleaseEvent)
		if !ok {
			return fmt.Errorf("invalid release event")
		}
		if handler.EnabledFeature(releaseNotes, derekConfig) {
			return handler.NewReleaseHandler(config, int(req.Installation.GetID())).Handle(*req)
		}
		return fmt.Errorf(`"release_notes" feature not enabled`)
	case "pull_request":
		// TODO: replace with github.PullRequestEvent
		req := types.PullRequestOuter{}
		if err := json.Unmarshal(bytesIn, &req); err != nil {
			return fmt.Errorf("Cannot parse input %s", err.Error())
		}

		if prIsClosed(req) {
			return nil
		}

		contributingURL := getContributingURL(derekConfig.ContributingURL, req.Repository.Owner.Login, req.Repository.Name)
		if handler.EnabledFeature(hacktoberfest, derekConfig) {
			isSpamPR, _ := handler.HandleHacktoberfestPR(req, contributingURL, config)
			if isSpamPR {
				return nil
			}
		}
		if handler.EnabledFeature(dcoCheck, derekConfig) {
			handler.HandlePullRequest(req, contributingURL, config)
		}
		if handler.EnabledFeature(prDescriptionRequired, derekConfig) {
			handler.VerifyPullRequestDescription(req, contributingURL, config)
		}
		return nil
	case "issue_comment":
		// TODO: replace with github.IssueCommentEvent
		req := types.IssueCommentOuter{}
		if err := json.Unmarshal(bytesIn, &req); err != nil {
			return fmt.Errorf("Cannot parse input %s", err.Error())
		}

		if req.Action == deleted {
			return nil
		}

		if handler.PermittedUserFeature(comments, derekConfig, req.Comment.User.Login) {
			handler.HandleComment(req, config, derekConfig)
		}
		return nil
	default:
		return fmt.Errorf("X_Github_Event want: ['pull_request', 'issue_comment'], got: " + eventType)
	}
}

func getContributingURL(contributingURL, owner, repositoryName string) string {
	if len(contributingURL) == 0 {
		contributingURL = fmt.Sprintf("https://github.com/%s/%s/blob/master/CONTRIBUTING.md", owner, repositoryName)
	}
	return contributingURL
}

func hmacValidation() bool {
	val := os.Getenv("validate_hmac")
	return (val != "false") && (val != "0")
}

func prIsClosed(req types.PullRequestOuter) bool {
	return req.Action == handler.ClosedConstant || req.PullRequest.State == handler.ClosedConstant
}

type githubActivityEvent interface {
	GetInstallation() *github.Installation
	GetRepo() *github.Repository
}

func getConfig(eventType string, payload interface{}, config config.Config) (repoConfig *types.DerekRepoConfig, err error) {
	if payload == nil {
		return nil, fmt.Errorf("Empty payload")
	}

	event, ok := payload.(githubActivityEvent)
	if !ok {
		return nil, fmt.Errorf("Invalid event payload")
	}

	repo := event.GetRepo()
	login := repo.Owner.GetLogin()
	name := repo.GetName()

	isCustomer, err := auth.IsCustomer(login, &http.Client{})
	if err != nil {
		return nil, fmt.Errorf("unable to verify customer: %s/%s", login, name)
	}

	if !isCustomer {
		return nil, fmt.Errorf("no customer found for: %s/%s", login, name)
	}

	if repo.GetPrivate() {
		repoConfig, err = handler.GetPrivateRepoConfig(login, name, int(event.GetInstallation().GetID()), config)
	} else {
		repoConfig, err = handler.GetRepoConfig(login, name)
	}

	if err != nil {
		return nil, fmt.Errorf(
			"Unable to access maintainers file at: %s/%s\nError: %s",
			login,
			name,
			err.Error(),
		)
	}

	return repoConfig, nil
}
