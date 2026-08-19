package sts

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awssts "github.com/aws/aws-sdk-go-v2/service/sts"
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
		return nil, fmt.Errorf("sts fail: %w", err)
	}
	if output.Credentials == nil {
		return nil, errors.New("sts credentials are empty")
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
		return nil, fmt.Errorf("sts fail: %w", err)
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
	cfg, err := config.LoadDefaultConfig(
		context.Background(),
		config.WithRegion(s.region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(s.accessKey, s.secretKey, "")),
	)
	if err != nil {
		return nil, err
	}

	return awssts.NewFromConfig(cfg), nil
}
