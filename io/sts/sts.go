package sts

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awssts "github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/tomtwinkle/aws-credential-tool/internal/errguide"
)

type SessionToken struct {
	AccessKey    string
	SecretKey    string
	SessionToken string
	Expiration   time.Time
	MFASerial    string
}

type Account struct {
	Account  string
	Arn      string
	UserId   string
	UserID   string
	UserName string
}

type Service interface {
	SessionToken(durationSeconds int64, serialNumber string, user string, token string) (*SessionToken, error)
	Account() (*Account, error)
}

type service struct {
	accessKey string
	secretKey string
	region    string
}

func NewService(accessKey string, secretKey string, region string) Service {
	return &service{accessKey: accessKey, secretKey: secretKey, region: region}
}

func (s *service) SessionToken(durationSeconds int64, account string, userName string, token string) (*SessionToken, error) {
	client, err := s.client()
	if err != nil {
		return nil, err
	}

	output, err := client.GetSessionToken(context.Background(), &awssts.GetSessionTokenInput{
		DurationSeconds: aws.Int32(int32(durationSeconds)),
		SerialNumber:    aws.String("arn:aws:iam::" + account + ":mfa/" + userName),
		TokenCode:       aws.String(token),
	})
	if err != nil {
		return nil, errguide.Wrap(fmt.Errorf("sts fail: %w", err), stsRepairSteps()...)
	}
	if output.Credentials == nil {
		return nil, errguide.New("sts credentials are empty",
			"Verify that the selected profile has valid long-lived credentials in aws-vault.",
			"Verify the AWS account permits GetSessionToken and retry the session-token action.",
		)
	}

	mfaSerial := "arn:aws:iam::" + account + ":mfa/" + userName
	return &SessionToken{
		AccessKey:    aws.ToString(output.Credentials.AccessKeyId),
		SecretKey:    aws.ToString(output.Credentials.SecretAccessKey),
		SessionToken: aws.ToString(output.Credentials.SessionToken),
		Expiration:   aws.ToTime(output.Credentials.Expiration),
		MFASerial:    mfaSerial,
	}, nil
}

func (s *service) Account() (*Account, error) {
	client, err := s.client()
	if err != nil {
		return nil, err
	}

	output, err := client.GetCallerIdentity(context.Background(), &awssts.GetCallerIdentityInput{})
	if err != nil {
		return nil, errguide.Wrap(fmt.Errorf("sts fail: %w", err), stsRepairSteps()...)
	}

	account := aws.ToString(output.Account)
	arn := aws.ToString(output.Arn)
	userID := aws.ToString(output.UserId)
	userName := ""
	if arn != "" {
		parts := strings.Split(arn, "/")
		userName = parts[len(parts)-1]
	}

	return &Account{
		Account:  account,
		Arn:      arn,
		UserId:   userID,
		UserID:   userID,
		UserName: userName,
	}, nil
}

func (s *service) client() (*awssts.Client, error) {
	loadOptions := []func(*config.LoadOptions) error{
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(s.accessKey, s.secretKey, "")),
	}
	if region := configuredRegion(s.region); region != "" {
		loadOptions = append(loadOptions, config.WithRegion(region))
	}

	cfg, err := config.LoadDefaultConfig(context.Background(), loadOptions...)
	if err != nil {
		return nil, errguide.Wrap(err,
			"Verify the AWS config and credential backend settings, then run actool again.",
			"If using a custom endpoint or proxy, verify that it is reachable from this environment.",
		)
	}
	if strings.TrimSpace(cfg.Region) == "" {
		return nil, errguide.New("AWS region is not configured",
			"Add `region = <region>` under `[default]` or `[profile <name>]` in `~/.aws/config`.",
			"Or set `AWS_REGION=<region>` (or `AWS_DEFAULT_REGION=<region>`).",
			"Run `actool` again and retry the session-token action.",
		)
	}

	return awssts.NewFromConfig(cfg), nil
}

func configuredRegion(profileRegion string) string {
	for _, name := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
		if region := strings.TrimSpace(os.Getenv(name)); region != "" {
			return region
		}
	}
	return strings.TrimSpace(profileRegion)
}

func stsRepairSteps() []string {
	return []string{
		"Verify the AWS region and profile configuration described above.",
		"If AWS_ENDPOINT_URL_STS is set, verify that the endpoint is reachable and intended.",
		"Confirm the selected profile has valid credentials, then run actool again.",
	}
}
