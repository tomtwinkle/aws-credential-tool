package toml

import (
	"fmt"
	"github.com/pkg/errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

type Toml interface {
	DecodeFile(fpath string) (*Model, error)
	Decode(data string) (*Model, error)
	WriteFile(fpath string, model *Model) error
}

type Model struct {
	Tables []*Table
}

type Table struct {
	Name    string
	Configs []*Config
}

func (t *Table) Config(key string) (string, bool) {
	for _, c := range t.Configs {
		if c.Key == key {
			return c.Value, true
		}
	}
	return "", false
}

type Config struct {
	Key   string
	Value string
}

type toml struct {
	regNewLine     *regexp.Regexp
	regMatchTable  *regexp.Regexp
	regMatchConfig *regexp.Regexp
}

func NewToml() Toml {
	regNewLine := regexp.MustCompile(`\r\n|\n\r|\n|\r`)
	regMatchTable := regexp.MustCompile(`^\s*\[([^\]]+)\]\s*$`)
	regMatchConfig := regexp.MustCompile(`^\s*([^=\s]+)\s*=\s*([^\s]+)\s*$`)
	return &toml{regNewLine: regNewLine, regMatchTable: regMatchTable, regMatchConfig: regMatchConfig}
}

func (t *toml) DecodeFile(fpath string) (*Model, error) {
	bs, err := ioutil.ReadFile(fpath)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return t.Decode(string(bs))
}

func (t *toml) Decode(data string) (*Model, error) {
	result, err := t.mapping(data)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return result, nil
}

func (t *toml) WriteFile(fpath string, model *Model) error {
	tmpDir := filepath.Dir(fpath)
	fName := filepath.Base(fpath)
	fp, err := ioutil.TempFile(tmpDir, fmt.Sprintf("%s.temp", fName))
	if err != nil {
		return errors.WithStack(err)
	}
	tmpPath := fp.Name()
	if model == nil {
		return errors.New("model is nil.")
	}
	str := t.modelToToml(model)

	if _, err := fp.WriteString(str); err != nil {
		return errors.WithStack(err)
	}
	if err := fp.Close(); err != nil {
		return errors.WithStack(err)
	}

	if _, err := os.Stat(fpath); err != nil {
		return errors.WithStack(err)
	}
	if err = os.Remove(fpath); err != nil {
		return errors.WithStack(err)
	}
	if err := os.Rename(tmpPath, fpath); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (t *toml) modelToToml(model *Model) string {
	var result = make([]string, 0)
	for _, t := range model.Tables {
		result = append(result, fmt.Sprintf("[%s]", t.Name))
		for _, c := range t.Configs {
			result = append(result, fmt.Sprintf("%s=%s", c.Key, c.Value))
		}
	}
	result = append(result, "")
	lineSep := "\n"
	if runtime.GOOS == "windows" {
		lineSep = "\r\n"
	}
	return strings.Join(result, lineSep)
}

// Does't conform to the toml specification. Not compatible with deep toml.
func (t *toml) mapping(data string) (*Model, error) {
	var mappingModel = new(Model)
	mappingModel.Tables = make([]*Table, 0)

	var tableIdx = -1

	lines := t.regNewLine.Split(data, -1)
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if t.regMatchTable.MatchString(line) {
			submatches := t.regMatchTable.FindAllStringSubmatch(line, -1)
			for _, submatch := range submatches {
				tableName := submatch[1]
				table := &Table{
					Name:    tableName,
					Configs: []*Config{},
				}
				mappingModel.Tables = append(mappingModel.Tables, table)
				tableIdx = len(mappingModel.Tables) - 1
			}
		}
		if t.regMatchConfig.MatchString(line) && tableIdx != -1 {
			submatches := t.regMatchConfig.FindAllStringSubmatch(line, -1)
			for _, submatch := range submatches {
				key := submatch[1]
				value := submatch[2]
				config := &Config{
					Key:   key,
					Value: value,
				}
				mappingModel.Tables[tableIdx].Configs = append(mappingModel.Tables[tableIdx].Configs, config)
			}
		}
	}

	return mappingModel, nil
}
