package generate

import (
	"reflect"
	"testing"
)

func Test_Params(t *testing.T) {
	p := Params{}

	if len(p.NamespaceSlice()) != 0 {
		t.Errorf("want empty slice but got none empty")
	}

	p = Params{
		Namespaces: "abc",
	}

	if !reflect.DeepEqual(p.NamespaceSlice(), []string{"abc"}) {
		t.Errorf("not equal")
	}
}
