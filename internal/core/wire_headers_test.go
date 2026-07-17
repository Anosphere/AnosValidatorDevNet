package core

import "testing"

func TestCheckAnosHeaders(t *testing.T) {
	const id = "305bffb513e844b51e10d2a1b3592b5327fe86970c2901fe3576f549fb331d82"
	cases := []struct {
		name          string
		gotID, gotVer string
		wantErr       bool
	}{
		{"match", id, "2", false},
		{"case-insensitive id", "305BFFB513E844B51E10D2A1B3592B5327FE86970C2901FE3576F549FB331D82", "2", false},
		{"wrong id", "deadbeef", "2", true},
		{"missing id", "", "2", true},
		{"wrong version (the pre-forquinn ruleset)", id, "1", true},
		{"missing version", id, "", true},
		{"both missing", "", "", true},
	}
	for _, c := range cases {
		err := CheckAnosHeaders(c.gotID, c.gotVer, id, 2)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: CheckAnosHeaders err=%v, wantErr=%v", c.name, err, c.wantErr)
		}
	}
}
