package scan

import "testing"

func TestCountCardMentions(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want int
	}{
		{"model = AutoModel.from_pretrained('x', trust_remote_code=True)", 1},
		{"trust_remote_code=true", 1},
		{"trust_remote_code = 1", 1},
		{"TRUST_REMOTE_CODE=True and trust_remote_code=True", 2},
		{"trust_remote_code: true", 0},
		{"no flag here", 0},
	}
	for _, tc := range cases {
		if got := CountCardMentions([]byte(tc.in)); got != tc.want {
			t.Fatalf("CountCardMentions(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func FuzzCountCardMentions(f *testing.F) {
	f.Add([]byte("trust_remote_code=True"))
	f.Add([]byte([]byte{0xff, 0xfe, 0x00}))
	f.Fuzz(func(t *testing.T, readme []byte) {
		if n := CountCardMentions(readme); n < 0 {
			t.Fatalf("negative count %d", n)
		}
	})
}
