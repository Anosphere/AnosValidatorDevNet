package core

import "testing"

func TestCheckAnosHeaders(t *testing.T) {
	const id = "82a4d3bd12d31fa2abb087710f524fc9f8b73e393480fc71cbd8066b53c339f7"
	cases := []struct {
		name          string
		gotID, gotVer string
		wantErr       bool
	}{
		{"match", id, "1", false},
		{"case-insensitive id", "82A4D3BD12D31FA2ABB087710F524FC9F8B73E393480FC71CBD8066B53C339F7", "1", false},
		{"wrong id", "deadbeef", "1", true},
		{"missing id", "", "1", true},
		{"wrong version", id, "2", true},
		{"missing version", id, "", true},
		{"both missing", "", "", true},
	}
	for _, c := range cases {
		err := CheckAnosHeaders(c.gotID, c.gotVer, id, 1)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: CheckAnosHeaders err=%v, wantErr=%v", c.name, err, c.wantErr)
		}
	}
}
