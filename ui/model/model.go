package model

type SelectMode int

const (
	SelectModeProfileSelect SelectMode = iota + 1
	SelectModeActionSelect
	SelectModeSTS
	SelectModeEnd
)
