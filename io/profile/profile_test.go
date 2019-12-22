package profile

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestProfile_Load(t *testing.T) {
	t.Run("load profile", func(t *testing.T) {
		p := NewProfile()
		actual, err := p.Load()
		assert.NoError(t, err)

		for _, c := range actual.Configs {
			fmt.Printf("%s=%+v\n", c.Name, c)
		}
		for _, c := range actual.Credentials {
			fmt.Printf("%s=%+v\n", c.Name, c)
		}
	})
}
