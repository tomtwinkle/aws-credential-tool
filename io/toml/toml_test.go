package toml

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestToml_DecodeFile(t *testing.T) {
	t.Run("load aws profile", func(t *testing.T) {
		toml := NewToml()
		actual, err := toml.DecodeFile("./example.toml")
		expected := &Model{
			[]*Table{
				{
					Name: "default",
					Configs: []*Config{
						{
							Key:   "aws_access_key_id",
							Value: "EXAMPLEAWSACCESSKEY1",
						},
						{
							Key:   "aws_secret_access_key",
							Value: "0-9A-Za-z!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
						},
					},
				},
				{
					Name: "profile1 hoge",
					Configs: []*Config{
						{
							Key:   "aws_access_key_id",
							Value: "EXAMPLEAWSACCESSKEY2",
						},
						{
							Key:   "aws_secret_access_key",
							Value: "0-9A-Za-z!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
						},
					},
				},
			},
		}
		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	})
}
