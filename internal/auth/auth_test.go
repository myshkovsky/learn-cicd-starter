package auth

import (
	"net/http"
	"reflect"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		fails   bool
		headers http.Header
		want    string
	}{
		"Valid ApiKey": {
			fails: true,
			headers: func() http.Header {
				header := http.Header{}
				header.Set("Authorization", "ApiKey 1234567890")
				return header
			}(),
			want: "1234567890",
		},
		"Invalid ApiKey": {
			fails: true,
			headers: func() http.Header {
				header := http.Header{}
				header.Set("Authorization", "NotAKey 1234567890")
				return header
			}(),
			want: "",
		},
		"Malformed ApiKey": {
			fails: true,
			headers: func() http.Header {
				header := http.Header{}
				header.Set("Authorization", "blehhhh")
				return header
			}(),
			want: "blehhhh",
		},
		"Valid ApiKey with special characters": {
			fails: false,
			headers: func() http.Header {
				header := http.Header{}
				header.Set("Authorization", "ApiKey 192(!@#&sczas&#!_)2{}{")
				return header
			}(),
			want: "192(!@#&sczas&#!_)2{}{",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.headers)
			if err != nil {
                if tc.fails {
                    return
                }
				t.Fatalf(err.Error())
            }
			if ok := reflect.DeepEqual(got, tc.want); !ok {
                if tc.fails {
                    return
                }
				t.Fatalf("%s: got: %s; want: %s;", name, got, tc.want)
			}
            if tc.fails {
                t.Fatalf("%s: Expected fail, but passed.", name)
            }
		})
	}
}
