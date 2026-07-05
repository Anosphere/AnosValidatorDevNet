package core

import "testing"

func TestCheckAnosHeaders(t *testing.T) {
	const id = "20bd2ec07a6eb9a6ca9314934f3b252767bce683150e4f3ec081f91578951ff2"
	cases := []struct {
		name          string
		gotID, gotVer string
		wantErr       bool
	}{
		{"match", id, "1", false},
		{"case-insensitive id", "20BD2EC07A6EB9A6CA9314934F3B252767BCE683150E4F3EC081F91578951FF2", "1", false},
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
