package model

type SelectMode int

const (
	SelectModeProfileSelect SelectMode = iota + 1
	SelectModeSTS
	SelectModeEnd
)

type Model struct {
	Message   string
	ListTitle string
	ListData  []string
}
