package guest

import "testing"

func TestBootstrapRefusesOrdinaryCodeProcessBeforeAnyMount(t *testing.T) {
	if e := Boot(); e == nil {
		t.Fatal("guest bootstrap admitted a host/code process")
	}
}
