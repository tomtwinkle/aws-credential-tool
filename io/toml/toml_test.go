package toml

import (
	"os"
	"path/filepath"
	"testing"

	"gotest.tools/v3/assert"
)

func TestTableConfig(t *testing.T) {
	table := &Table{Configs: []*Config{{Key: "region", Value: "ap-northeast-1"}}}
	cases := []struct {
		name  string
		key   string
		value string
		found bool
	}{
		{name: "existing key", key: "region", value: "ap-northeast-1", found: true},
		{name: "missing key", key: "output", found: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value, found := table.Config(tc.key)
			assert.Equal(t, value, tc.value)
			assert.Equal(t, found, tc.found)
		})
	}
}

func TestTomlDecode(t *testing.T) {
	cases := []struct {
		name string
		data string
		want *Model
	}{
		{
			name: "aws profiles",
			data: "[default]\naws_access_key_id = EXAMPLEAWSACCESSKEY1\naws_secret_access_key = SECRET1\n\n[profile1 hoge]\naws_access_key_id = EXAMPLEAWSACCESSKEY2\naws_secret_access_key = SECRET2\n",
			want: &Model{Tables: []*Table{
				{Name: "default", Configs: []*Config{{Key: "aws_access_key_id", Value: "EXAMPLEAWSACCESSKEY1"}, {Key: "aws_secret_access_key", Value: "SECRET1"}}},
				{Name: "profile1 hoge", Configs: []*Config{{Key: "aws_access_key_id", Value: "EXAMPLEAWSACCESSKEY2"}, {Key: "aws_secret_access_key", Value: "SECRET2"}}},
			}},
		},
		{
			name: "ignores values before first table",
			data: "orphan = value\n[default]\nregion = ap-northeast-1\n",
			want: &Model{Tables: []*Table{{Name: "default", Configs: []*Config{{Key: "region", Value: "ap-northeast-1"}}}}},
		},
		{name: "empty document", data: "\n\r\n", want: &Model{Tables: []*Table{}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := NewToml().Decode(tc.data)
			assert.NilError(t, err)
			assert.DeepEqual(t, actual, tc.want)
		})
	}
}

func TestTomlDecodeFile(t *testing.T) {
	actual, err := NewToml().DecodeFile("./example.toml")
	assert.NilError(t, err)
	assert.DeepEqual(t, actual, &Model{
		Tables: []*Table{
			{
				Name: "default",
				Configs: []*Config{
					{Key: "aws_access_key_id", Value: "EXAMPLEAWSACCESSKEY1"},
					{Key: "aws_secret_access_key", Value: "0-9A-Za-z!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"},
				},
			},
			{
				Name: "profile1 hoge",
				Configs: []*Config{
					{Key: "aws_access_key_id", Value: "EXAMPLEAWSACCESSKEY2"},
					{Key: "aws_secret_access_key", Value: "0-9A-Za-z!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"},
				},
			},
		},
	})
}

func TestTomlDecodeFileErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.toml")
	_, err := NewToml().DecodeFile(path)
	assert.Assert(t, err != nil)
}

func TestTomlWriteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	assert.NilError(t, os.WriteFile(path, []byte("[old]\nvalue = old\n"), 0o600))

	model := &Model{Tables: []*Table{{Name: "default", Configs: []*Config{{Key: "region", Value: "ap-northeast-1"}}}}}
	assert.NilError(t, NewToml().WriteFile(path, model))
	contents, err := os.ReadFile(path)
	assert.NilError(t, err)
	assert.Equal(t, string(contents), "[default]\nregion = ap-northeast-1\n")
}

func TestTomlWriteFileRejectsNilModel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	assert.NilError(t, os.WriteFile(path, []byte("[old]\nvalue = old\n"), 0o600))
	assert.Error(t, NewToml().WriteFile(path, nil), "model is nil.")
}
