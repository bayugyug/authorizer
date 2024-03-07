package validator_test

import (
	"testing"

	"github.com/bayugyug/authorizer/commons/validator"
)

type testCase struct {
	name        string
	input       interface{}
	expected    string
	expectedNil bool
}

var tests = []*testCase{
	// --- invalid cases ---
	{
		name: `required`,
		input: struct {
			Email string `json:"email" form:"required"`
		}{},
		expected: "Email is a required field",
	},
	{
		name: `min`,
		input: struct {
			Age int `json:"age" form:"min=16"`
		}{Age: 7},
		expected: "Age must be a minimum of 16 in length",
	},
	{
		name: `max`,
		input: struct {
			Course string `json:"course" form:"max=7"`
		}{Course: "CS-0001."},
		expected: "Course must be a maximum of 7 in length",
	},
	{
		name: `url`,
		input: struct {
			Host string `json:"host" form:"url"`
		}{Host: "foobar.com"},
		expected: "Host must be a valid URL",
	},
	{
		name: `ip`,
		input: struct {
			Host string `json:"host" form:"ip"`
		}{Host: "172.16.256.255"},
		expected: "Host must be a valid IP address",
	},
	{
		name: `ipv4`,
		input: struct {
			Host string `json:"host" form:"ipv4"`
		}{Host: "192.168.255.256"},
		expected: "Host must be a valid IPv4 address",
	},
	{
		name: `ipv6`,
		input: struct {
			Host string `json:"host" form:"ipv6"`
		}{Host: "172.16.255.254"},
		expected: "Host must be a valid IPv6 address",
	},
}

func TestToErrResponse(t *testing.T) {
	vr := validator.New()

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := vr.Struct(tc.input)
			errResp := validator.ToErrResponse(err)
			if tc.expectedNil && errResp != nil {
				t.Fatalf(`Expected: nil, Got:"%v"`, errResp)
			}

			if !tc.expectedNil {
				if errResp == nil || len(errResp.Errors) != 1 {
					t.Fatalf(`Expected:"{[%v]}", Got:"%v"`, tc.expected, errResp)
				} else if errResp.Errors[0] != tc.expected {
					t.Fatalf(`Expected:"%v", Got:"%v"`, tc.expected, errResp.Errors[0])
				}
			}
		})
	}
}
