package sts

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
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
	Account   string
	Arn       string
	UserId    string
	UserID    string
	UserName  string
	MFASerial string
}

type Service interface {
	SessionToken(durationSeconds int64, serialNumber string, user string, token string) (*SessionToken, error)
	Account() (*Account, error)
}

type service struct {
	accessKey string
	secretKey string
	region    string
	mfaSerial string
}

func NewService(accessKey string, secretKey string, region string) Service {
	return NewServiceWithMFASerial(accessKey, secretKey, region, "")
}

func NewServiceWithMFASerial(accessKey string, secretKey string, region string, mfaSerial string) Service {
	return &service{accessKey: accessKey, secretKey: secretKey, region: region, mfaSerial: mfaSerial}
}

func (s *service) SessionToken(durationSeconds int64, serialNumber string, userName string, token string) (*SessionToken, error) {
	mfaSerial, err := s.resolveMFASerial(serialNumber, userName)
	if err != nil {
		return nil, err
	}

	client, err := s.client()
	if err != nil {
		return nil, err
	}

	output, err := client.GetSessionToken(context.Background(), &awssts.GetSessionTokenInput{
		DurationSeconds: aws.Int32(int32(durationSeconds)),
		SerialNumber:    aws.String(mfaSerial),
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
	mfaSerial, userName := mfaSerialFromCallerARN(arn, account)

	return &Account{
		Account:   account,
		Arn:       arn,
		UserId:    userID,
		UserID:    userID,
		UserName:  userName,
		MFASerial: mfaSerial,
	}, nil
}

func (s *service) resolveMFASerial(serialNumber string, userName string) (string, error) {
	if configured := strings.TrimSpace(s.mfaSerial); configured != "" {
		return configured, nil
	}

	serialNumber = strings.TrimSpace(serialNumber)
	if strings.HasPrefix(serialNumber, "arn:") {
		return serialNumber, nil
	}
	if serialNumber == "" || strings.TrimSpace(userName) == "" {
		return "", errguide.New("MFA serial number is not available",
			"Set `mfa_serial = <MFA device serial or ARN>` under the selected AWS profile.",
			"Use long-lived IAM user credentials when requesting an STS session token.",
			"Run actool again after saving the AWS config.",
		)
	}

	region := configuredRegion(s.region)
	return fmt.Sprintf("arn:%s:iam::%s:mfa/%s", partitionForRegion(region), serialNumber, userName), nil
}

func mfaSerialFromCallerARN(callerARN string, account string) (string, string) {
	parsed, err := awsarn.Parse(callerARN)
	if err != nil {
		return "", lastARNPart(callerARN)
	}

	userName := lastARNPart(parsed.Resource)
	if parsed.Service != "iam" || !strings.HasPrefix(parsed.Resource, "user/") || userName == "" {
		return "", userName
	}
	accountID := parsed.AccountID
	if accountID == "" {
		accountID = account
	}
	if parsed.Partition == "" || accountID == "" {
		return "", userName
	}
	return fmt.Sprintf("arn:%s:iam::%s:mfa/%s", parsed.Partition, accountID, userName), userName
}

func lastARNPart(value string) string {
	parts := strings.Split(value, "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func partitionForRegion(region string) string {
	switch {
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn"
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov"
	case strings.HasPrefix(region, "us-isof-"):
		return "aws-iso-f"
	case strings.HasPrefix(region, "us-isob-"):
		return "aws-iso-b"
	case strings.HasPrefix(region, "us-iso-"):
		return "aws-iso"
	case strings.HasPrefix(region, "eu-isoe-"):
		return "aws-iso-e"
	case strings.HasPrefix(region, "eusc-de-"):
		return "aws-eusc"
	default:
		return "aws"
	}
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
