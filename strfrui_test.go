package strfrui_test

import (
	"github.com/jiftechnify/strfrui"
	"github.com/jiftechnify/strfrui/sifters"
)

func ExampleRunner() {
	strfrui.New(sifters.KindList([]int{1}, sifters.Allow)).Run()
}
