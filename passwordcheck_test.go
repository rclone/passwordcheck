package main

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPassword(t *testing.T) {
	*verbose = true
	var pw = make([]byte, 8)
	rng := rand.New(rand.NewSource(1))
	password(rng, pw)
	pass := passString(pw)
	assert.Equal(t, "Uv38ByGCZU8", pass)
}

func TestReadConfigFile(t *testing.T) {
	configFile := `# Test config file
[not-obscured]
thing = one
pass = 
passloner
password = !!!!!!
other_thing = potato

[notbase64]
password = ct8QRft_SpEY-0Pe5_DozADqGaEFj0k

[tooshort]
password2 = DFB6TIJMQaf87W2ezkwAxXCBAfuahowkvp8

[length64]
pass = dxoMOzkcjpW2PWdavebc1CUyrIGtKyVOc_PU

[length64-2]
password = x72I-rX4PJzQLxdoIV7kHB9nxn3I1u0aFAhS
password2 = i6xt2_n2F_zHF1TvYzWCDicCf_uxlrKTRMwz

[length128]
pass = uBc9tsG45TQ_DrIP76WXIKOQkmWR5WhhBwqWesYvorcdXijhsnY

`
	want := map[int][]passEntry{
		8: []passEntry{
			{
				remote:   "length64",
				obscured: "dxoMOzkcjpW2PWdavebc1CUyrIGtKyVOc_PU",
				pw:       []byte("!!!!!!!!"),
			},
			{
				remote:   "length64-2",
				obscured: "x72I-rX4PJzQLxdoIV7kHB9nxn3I1u0aFAhS",
				pw:       []byte("0!!!!!!!"),
			},
			{
				remote:   "length64-2",
				obscured: "i6xt2_n2F_zHF1TvYzWCDicCf_uxlrKTRMwz",
				pw:       []byte("1!!!!!!!"),
			},
		},
		16: []passEntry{
			{
				remote:   "length128",
				obscured: "uBc9tsG45TQ_DrIP76WXIKOQkmWR5WhhBwqWesYvorcdXijhsnY",
				pw:       []byte("!!!!!!!!!!!!!!!!"),
			},
		},
	}

	got := readConfigFile(bytes.NewBufferString(configFile))
	assert.Equal(t, want, got)

}

func TestPasswords(t *testing.T) {
	configFile := `
[bad64]
type = crypt
remote = /tmp/crypt
password = fJKeinHaUgkd_4pO0J70tUMUkvoxoPES5p7-
password2 = hMd7p9RguIcMzGV3pJ4aV9SuHJrl3Y9MAB8I

[bad128-1]
type = crypt
remote = /tmp
password = r-zxEh10ufF9r48najyPn9UrmECuMhWTkIsEubDKtZ3fehFHMwY

[bad128-2]
type = crypt
remote = /tmp
password = px0py_poF8Jzis0rxNGf2OvtVZPnmwUruqI1o3trhE1I8fcR3To

[ok-64]
pass = dxoMOzkcjpW2PWdavebc1CUyrIGtKyVOc_PU
`
	pwMap := readConfigFile(bytes.NewBufferString(configFile))
	startSeed := timeParse("2020-11-18 00:00:00")
	endSeed := timeParse("2020-11-20 00:00:00")
	gotPws := findAllPasswords(startSeed, endSeed, pwMap)
	wantPws := []passEntry{
		{
			remote:   "bad64",
			obscured: "fJKeinHaUgkd_4pO0J70tUMUkvoxoPES5p7-",
			pw:       []byte{0x6d, 0xcd, 0xbb, 0xff, 0x61, 0xf6, 0x05, 0xc9},
		},
		{
			remote:   "bad128-1",
			obscured: "r-zxEh10ufF9r48najyPn9UrmECuMhWTkIsEubDKtZ3fehFHMwY",
			pw:       []byte{0x6d, 0x92, 0xf2, 0x95, 0x9b, 0x19, 0xe4, 0xd0, 0x36, 0x83, 0x8b, 0x01, 0x10, 0xf0, 0x94, 0x0b},
		},
		{
			remote:   "bad128-2",
			obscured: "px0py_poF8Jzis0rxNGf2OvtVZPnmwUruqI1o3trhE1I8fcR3To",
			pw:       []byte{0x5b, 0x9a, 0x79, 0xc1, 0xf5, 0xae, 0x40, 0x1c, 0x73, 0xd5, 0xa0, 0xa3, 0xae, 0xea, 0x0c, 0x81},
		},
	}
	assert.Equal(t, wantPws, gotPws)

}
