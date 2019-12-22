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
					Configs: map[string]*Config{
						"aws_access_key_id": {
							Key:   "aws_access_key_id",
							Value: "EXAMPLEAWSACCESSKEY1",
						},
						"aws_secret_access_key": {
							Key:   "aws_secret_access_key",
							Value: "0-9A-Za-z!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
						},
					},
				},
				{
					Name: "profile1 hoge",
					Configs: map[string]*Config{
						"aws_access_key_id": {
							Key:   "aws_access_key_id",
							Value: "EXAMPLEAWSACCESSKEY2",
						},
						"aws_secret_access_key": {
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
