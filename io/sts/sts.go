package sts

type STS interface {
	GetSession() (*session, error)
}

type sts struct {}

type session struct {
	accessKey string
	secretKey string
	sessionKey string
}

func NewSTS() STS {
	return &sts{}
}

func (s *sts) GetSession() (*session, error) {
	session := &session{}

	return session, nil
}

