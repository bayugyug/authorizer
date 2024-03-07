package validator

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
)

// ErrResponse ...
type ErrResponse struct {
	Errors []string `json:"errors"`
}

// New ...
func New() *validator.Validate {
	validate := validator.New()
	validate.SetTagName("form")

	// Using the names which have been specified for JSON representations of structs, rather than normal Go field names
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})

	_ = validate.RegisterValidation("conjunction", Conjunction, true)

	return validate
}

// ToErrResponse ...
func ToErrResponse(err error) *ErrResponse {
	if fieldErrors, ok := err.(validator.ValidationErrors); ok {
		resp := ErrResponse{
			Errors: make([]string, len(fieldErrors)),
		}

		for i, err := range fieldErrors {
			switch err.Tag() {
			case "required":
				resp.Errors[i] = fmt.Sprintf("%s is a required field", err.StructField())
			case "conjunction":
				resp.Errors[i] = fmt.Sprintf("%s cannot be used in conjunction with %s", err.StructField(), err.Param())
			case "oneof":
				resp.Errors[i] = fmt.Sprintf("%s must be one of %s", err.StructField(), err.Param())
			case "min":
				resp.Errors[i] = fmt.Sprintf("%s must be a minimum of %s in length", err.StructField(), err.Param())
			case "max":
				resp.Errors[i] = fmt.Sprintf("%s must be a maximum of %s in length", err.StructField(), err.Param())
			case "email":
				resp.Errors[i] = fmt.Sprintf("%s must be a valid email address", err.StructField())
			case "url":
				resp.Errors[i] = fmt.Sprintf("%s must be a valid URL", err.StructField())
			case "ip":
				resp.Errors[i] = fmt.Sprintf("%s must be a valid IP address", err.StructField())
			case "ipv4":
				resp.Errors[i] = fmt.Sprintf("%s must be a valid IPv4 address", err.StructField())
			case "ipv6":
				resp.Errors[i] = fmt.Sprintf("%s must be a valid IPv6 address", err.StructField())
			default:
				resp.Errors[i] = fmt.Sprintf("something wrong on %s; %s", err.StructField(), err.Tag())
			}
		}

		return &resp
	}

	return nil
}

// Conjunction ...
func Conjunction(fl validator.FieldLevel) bool {
	field := fl.Field()
	kind := field.Kind()
	if !hasValue(field, true) {
		return true
	}

	var nullable, found bool
	currentField, currentKind, nullable, found := fl.GetStructFieldOK2()

	if !found || currentKind != kind {
		return true
	}

	return !hasValue(currentField, nullable)
}

func hasValue(field reflect.Value, nullable bool) bool {
	switch field.Kind() {
	case reflect.Slice, reflect.Map, reflect.Ptr, reflect.Interface, reflect.Chan, reflect.Func:
		return !field.IsNil()
	default:
		if nullable && field.Interface() != nil {
			return true
		}
		return field.IsValid() && field.Interface() != reflect.Zero(field.Type()).Interface()
	}
}
