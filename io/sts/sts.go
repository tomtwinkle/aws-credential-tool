package sts

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
	"strings"
	"time"
)

type SessionToken struct {
	AccessKey    string
	SecretKey    string
	SessionToken string
	Expiration   time.Time
}

type Account struct {
	Account  string
	Arn      string
	UserId   string
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
	sess := session.Must(session.NewSession())
	creds := credentials.NewStaticCredentials(s.accessKey, s.secretKey, "")
	svc := sts.New(
		sess,
		aws.NewConfig().WithRegion(s.region).WithCredentials(creds),
	)
	input := &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int64(durationSeconds),
		SerialNumber:    aws.String(fmt.Sprintf("arn:aws:iam::%s:mfa/%s", account, userName)),
		TokenCode:       aws.String(token),
	}
	output, err := svc.GetSessionToken(input)
	if err != nil {
		return nil, errors.WithMessage(err, "sts fail")
	}

	return &SessionToken{
		AccessKey:    *output.Credentials.AccessKeyId,
		SecretKey:    *output.Credentials.SecretAccessKey,
		SessionToken: *output.Credentials.SessionToken,
		Expiration:   *output.Credentials.Expiration,
	}, nil
}

func (s *service) Account() (*Account, error) {
	sess := session.Must(session.NewSession())
	creds := credentials.NewStaticCredentials(s.accessKey, s.secretKey, "")
	svc := sts.New(
		sess,
		aws.NewConfig().WithRegion(s.region).WithCredentials(creds),
	)
	input := &sts.GetCallerIdentityInput{}
	output, err := svc.GetCallerIdentity(input)
	if err != nil {
		return nil, errors.WithMessage(err, "sts fail")
	}

	var account, userId, userName, arn string
	if output.Account != nil && output.Arn != nil && output.UserId != nil {
		account = *output.Account
		userId = *output.UserId
		arn = *output.Arn
		userName = strings.Split(arn, "/")[1]
	}

	return &Account{
		Account:  account,
		Arn:      arn,
		UserId:   userId,
		UserName: userName,
	}, nil
}
