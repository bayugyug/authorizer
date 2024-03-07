package authorizer_test

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/icrowley/fake"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/bayugyug/authorizer"
	"github.com/bayugyug/authorizer/commons"
)

var _ = Describe("Authverifier", func() {

	var (
		router   *chi.Mux
		verifier authorizer.VerifierServiceCreator
		// sample keys only :-)
		privKeyStr = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA5wZ+Lv2WhNG3Eg4KeBneUSFYOKo03aZB9NfgZkXmpk1ydw/K\\nlr8Vq7cOXqJ7JuS7BMwtvSjGsM5Z1SFlfUBcygBig2ghp+MtGPzGh2iT4jHvLzIE\\nBjdyLZS9sh8kS/JoMMwaNV//1W8Z0lMRQNzHOzyilzzHsB389F1Ujlu5jVekkY1b\\nattnrEhvK1DZbQ8BwXH8rLNCxky8uwgMu/PUPsDeqnx2Cc/9bH0ptetsdMysFirl\\ndcFA1wKZaJbomACFBF3DWWYETkRsf6wgMcs8PRp2UV1gPnIW9CarF5WjqgxjLKxA\\n/Pj5p9n1q4V04s+EWKjowgJ+8zDibC/JRrBqWwIDAQABAoIBAQC6UspCK9PRmzID\\nJb/bzUE4PaRhTyUD/qsDRXh+A7JaPewriljh64sWyrSULocUfzU2UVYyUUiuID7j\\nXeP0eIxdfqH1SW6bcOVWWcfkPbvHmm5FqhkEyoMTr/quRd+IQSE2+eXJVnuHL+ur\\nbcNkhKtKY0TepO6IZCc3Dm67wc6M5rJQ8/904cpXFK+G2BUOpFNKvi6dx0+ygYBO\\nIVn7VlihIBbcY1m+lijZX4l/zgyHpZd4oJTzXbxr9hND/5xgVDXsMn3wPK0gg6L8\\njnLog+3H0Dr9bd/jxi4EdS62Pt4UPzM7i7H0VCrlJLF+6JeFB3YBkBjzixjm+CAu\\nYHdBQDWBAoGBAPUza9L8pxshNf1+GrSj/2hVClSx7WzRxF2N7rA70Oq072XGUbyA\\n3+I2O+HHaGNbtpcc1n340l534q/MDvOIWB8AlB+f3B+w1rct2x9wJmkls9YYe3gK\\n9BXco0XChmnf5b1F+Qdos/MrIh6I/IAIYOfKJpg+8KTVdWaIqMtV7dJjAoGBAPEz\\nPxhBGNTPvG7UvDBMo2ivPGh+QCvs7ronyGFITPjYjFkY4/tvDjccpDnygUVcQ02/\\nIbw1Rv7XnXSzzdDfOLMySCMwPwIdZ81DoM324zcUJ+GZb2xbwmwi7ZXdiZEv87LU\\nTPINcJ6F8R1diUYn0HiiKbA810i6a1wVvXFR8I2pAoGAIpMKnCiGA5xOOZ1DdL8/\\nL132Y/TmzpZRgwOVaYI1tjKnIwmw0sy1RPdywCZXANOYznwBfqfMOgfbjgBPB2Xt\\nTwnM2Ry4dDuCOzgbErbEo8TuM70mA8o/mqmO2DJSs7Efeu3X7ISGAz7Mw9N7Dy6f\\nQ2/Mu2D8m7GBqWCRtII8U5MCgYAnoGK6Sl+Y/vQXRU4RpVWnajrDdBJ45Pknjkem\\na+lxbKpKLQOvmEQ+m68Dcir4yTqpeEBDmoEqdyQAO1YR/cpj7lvZpCCF6WzXVUgC\\n7o/PybjvoHSk2cJsX6Sm3XmvZ7Bi7ewiTED3WkwNpgNaikn+t62fra803KOswkmY\\nZ3zc2QKBgAsEZH5xX582S8Xwf8l8sjcvrwOPGF/a+S4S3nbH9k+zi3zLZ5iX9Pfj\\nW60tFPBz06q+PQ31Hp1oVD+hnMa6kZi1DbpQqPIQsgAKzeqGg+R2qSyxtFC8pw64\\nLje6XP701YgVCmCkRM1nTBbRq0NvbdwcepnZDriyl1mBCBFS8GiU\\n-----END RSA PRIVATE KEY-----"
		pubKeyStr  = "-----BEGIN RSA PUBLIC KEY-----\\nMIIBCgKCAQEA5wZ+Lv2WhNG3Eg4KeBneUSFYOKo03aZB9NfgZkXmpk1ydw/Klr8V\\nq7cOXqJ7JuS7BMwtvSjGsM5Z1SFlfUBcygBig2ghp+MtGPzGh2iT4jHvLzIEBjdy\\nLZS9sh8kS/JoMMwaNV//1W8Z0lMRQNzHOzyilzzHsB389F1Ujlu5jVekkY1battn\\nrEhvK1DZbQ8BwXH8rLNCxky8uwgMu/PUPsDeqnx2Cc/9bH0ptetsdMysFirldcFA\\n1wKZaJbomACFBF3DWWYETkRsf6wgMcs8PRp2UV1gPnIW9CarF5WjqgxjLKxA/Pj5\\np9n1q4V04s+EWKjowgJ+8zDibC/JRrBqWwIDAQAB\\n-----END RSA PUBLIC KEY-----"
		salt       = fake.DigitsN(12)
	)

	BeforeEach(func() {
		router = chi.NewRouter()
	})

	AfterEach(func() {
	})

	Context("Sign payload", func() {
		It("Prepare", func() {
			log.Println("check")
			opts := authorizer.Options{
				PrivateKey: privKeyStr,
				PublicKey:  pubKeyStr,
				TokenSource: authorizer.TokenSource{
					QueryKey: "_verify",
				},
				Expiry: 1400,
			}
			verifier = authorizer.NewVerifierService(&opts)
			Expect(verifier).NotTo(BeNil())
			claims := &authorizer.AuthClaims{
				StandardClaims: jwt.StandardClaims{
					Audience:  "ci-verifier-aud",
					Id:        uuid.New().String(),
					Issuer:    "ci-test",
					Subject:   salt,                                                     // salt
					ExpiresAt: time.Now().Add(time.Duration(3600) * time.Minute).Unix(), // expiry
				},
				MetaInfo: map[string]interface{}{
					"more": fake.Sentences(),
				},
			}

			// sign
			sign, err := verifier.Sign(claims)
			commons.JSONify(sign, err)
			Expect(len(sign)).Should(BeNumerically(">", 0))
			Expect(err).To(BeNil())
			log.Println("signed token", sign)
			By("Sign payload ok")
		})
	})

	Context("Sign private key invalid", func() {
		It("Prepare", func() {

			opts := authorizer.Options{
				PrivateKey: privKeyStr + fake.Brand(),
				PublicKey:  pubKeyStr,
				TokenSource: authorizer.TokenSource{
					QueryKey: "_verify",
				},
				Expiry: 1400,
			}
			verifier = authorizer.NewVerifierService(&opts)
			Expect(verifier).NotTo(BeNil())
			claims := &authorizer.AuthClaims{
				StandardClaims: jwt.StandardClaims{
					Audience:  "ci-verifier-aud",
					Id:        uuid.New().String(),
					Issuer:    "ci-test",
					Subject:   salt,                                                     // salt
					ExpiresAt: time.Now().Add(time.Duration(3600) * time.Minute).Unix(), // expiry
				},
				MetaInfo: map[string]interface{}{
					"more": fake.Sentences(),
				},
			}

			// sign
			sign, err := verifier.Sign(claims)
			commons.JSONify(sign, err)
			Expect(len(sign)).Should(BeNumerically("<=", 0))
			Expect(err).NotTo(BeNil())

			By("Sign private key invalid ok")
		})
	})

	Context("Unsign payload", func() {
		It("Prepare", func() {

			opts := authorizer.Options{
				PrivateKey: privKeyStr,
				PublicKey:  pubKeyStr,
				TokenSource: authorizer.TokenSource{
					QueryKey: "_verify",
				},
				Expiry: 1400,
			}
			verifier = authorizer.NewVerifierService(&opts)
			Expect(verifier).NotTo(BeNil())

			claims := &authorizer.AuthClaims{
				StandardClaims: jwt.StandardClaims{
					Audience:  "ci-verifier-aud",
					Id:        uuid.New().String(),
					Issuer:    "ci-test",
					Subject:   salt,                                                     // salt
					ExpiresAt: time.Now().Add(time.Duration(3600) * time.Minute).Unix(), // expiry
				},
				MetaInfo: map[string]interface{}{
					"more": fake.Sentences(),
				},
			}

			// handler
			proxyHandler := func(w http.ResponseWriter, r *http.Request) {
				// check jwt
				res, err := verifier.UnSign(r)
				if err != nil {
					render.Status(r, http.StatusInternalServerError)
					render.JSON(w, r,
						err.Error(),
					)
					return
				}
				log.Printf("RES:%#v\n", res)
			}

			// sign
			sign, err := verifier.Sign(claims)
			commons.JSONify(sign, err)
			Expect(len(sign)).Should(BeNumerically(">", 0))
			Expect(err).To(BeNil())

			log.Println("sign", sign)

			router.Method(http.MethodGet,
				"/get",
				http.HandlerFunc(proxyHandler))

			w, b := commons.HTTPDummyReq(router,
				http.MethodGet,
				fmt.Sprintf("/get?_verify=%s", url.QueryEscape(sign)),
				nil,
				nil)
			Expect(w.Code).To(Equal(http.StatusOK))

			log.Println("RAW", w.Code, string(b))

			By("Unsign payload ok")
		})
	})

	Context("Unsign payload fail", func() {
		It("Prepare", func() {

			opts := authorizer.Options{
				PrivateKey: privKeyStr,
				PublicKey:  pubKeyStr,
				TokenSource: authorizer.TokenSource{
					QueryKey: "_verify",
				},
				Expiry: 1400,
			}
			verifier = authorizer.NewVerifierService(&opts)
			Expect(verifier).NotTo(BeNil())

			claims := &authorizer.AuthClaims{
				StandardClaims: jwt.StandardClaims{
					Audience:  "ci-verifier-aud",
					Id:        uuid.New().String(),
					Issuer:    "ci-test",
					Subject:   salt,                                                      // salt
					ExpiresAt: time.Now().Add(time.Duration(-3600) * time.Minute).Unix(), // expiry
				},
				MetaInfo: map[string]interface{}{
					"more": fake.Sentences(),
				},
			}

			// handler
			proxyHandler := func(w http.ResponseWriter, r *http.Request) {
				// check jwt
				res, err := verifier.UnSign(r)
				if err != nil {
					render.Status(r, http.StatusInternalServerError)
					render.JSON(w, r,
						err.Error(),
					)
					return
				}
				log.Printf("RES:%#v\n", res)
			}

			// sign
			sign, err := verifier.Sign(claims)
			commons.JSONify(sign, err)
			Expect(len(sign)).Should(BeNumerically(">", 0))
			Expect(err).To(BeNil())

			log.Println("sign", sign)

			router.Method(http.MethodGet,
				"/get",
				http.HandlerFunc(proxyHandler))

			w, b := commons.HTTPDummyReq(router,
				http.MethodGet,
				fmt.Sprintf("/get?_verify=%s", url.QueryEscape(sign)),
				nil,
				nil)
			Expect(w.Code).NotTo(Equal(http.StatusOK))

			log.Println("RAW", w.Code, string(b))

			By("Unsign payload fail ok")
		})
	})

	Context("Unsign payload expired", func() {
		It("Prepare", func() {

			opts := authorizer.Options{
				PrivateKey: privKeyStr,
				PublicKey:  pubKeyStr,
				TokenSource: authorizer.TokenSource{
					QueryKey: "_verify",
				},
				Expiry: 1400,
			}
			verifier = authorizer.NewVerifierService(&opts)
			Expect(verifier).NotTo(BeNil())

			claims := &authorizer.AuthClaims{
				StandardClaims: jwt.StandardClaims{
					Audience:  "ci-verifier-aud",
					Id:        uuid.New().String(),
					Issuer:    "ci-test",
					Subject:   salt,                                                     // salt
					ExpiresAt: time.Now().Add(time.Duration(3600) * time.Minute).Unix(), // expiry
				},
				MetaInfo: map[string]interface{}{
					"more": fake.Sentences(),
				},
			}

			// handler
			proxyHandler := func(w http.ResponseWriter, r *http.Request) {
				// check jwt
				res, err := verifier.UnSign(r)
				if err != nil {
					render.Status(r, http.StatusInternalServerError)
					render.JSON(w, r,
						err.Error(),
					)
					return
				}
				log.Printf("RES:%#v\n", res)
			}

			// sign
			sign, err := verifier.Sign(claims)
			commons.JSONify(sign, err)
			Expect(len(sign)).Should(BeNumerically(">", 0))
			Expect(err).To(BeNil())

			log.Println("sign", sign)

			router.Method(http.MethodGet,
				"/get",
				http.HandlerFunc(proxyHandler))

			w, b := commons.HTTPDummyReq(router,
				http.MethodGet,
				fmt.Sprintf("/get?_verify=%s%s", url.QueryEscape(sign), fake.DigitsN(120)),
				nil,
				nil)
			Expect(w.Code).NotTo(Equal(http.StatusOK))

			log.Println("RAW", w.Code, string(b))

			By("Unsign payload expired ok")
		})
	})

	Context("Unsign payload and check salt", func() {
		It("Prepare", func() {

			opts := authorizer.Options{
				PrivateKey: privKeyStr,
				PublicKey:  pubKeyStr,
				TokenSource: authorizer.TokenSource{
					QueryKey: "_verify",
				},
				Expiry: 1400,
			}
			verifier = authorizer.NewVerifierService(&opts)
			Expect(verifier).NotTo(BeNil())

			claims := &authorizer.AuthClaims{
				StandardClaims: jwt.StandardClaims{
					Audience:  "ci-verifier-aud",
					Id:        uuid.New().String(),
					Issuer:    "ci-test",
					Subject:   salt,                                                     // salt
					ExpiresAt: time.Now().Add(time.Duration(3600) * time.Minute).Unix(), // expiry
				},
				MetaInfo: map[string]interface{}{
					"more": fake.Sentences(),
				},
			}

			// handler
			proxyHandler := func(w http.ResponseWriter, r *http.Request) {
				// check jwt
				res, err := verifier.UnSign(r)
				if err != nil {
					render.Status(r, http.StatusInternalServerError)
					render.JSON(w, r,
						err.Error(),
					)
					return
				}
				log.Printf("RES:%#v\n", res)
				oks := res.CheckSubject(salt)
				commons.JSONify("check salt", res, oks)
				if !oks {
					render.Status(r, http.StatusInternalServerError)
					render.JSON(w, r,
						err.Error(),
					)
					return
				}
			}

			// sign
			sign, err := verifier.Sign(claims)
			commons.JSONify(sign, err)
			Expect(len(sign)).Should(BeNumerically(">", 0))
			Expect(err).To(BeNil())

			log.Println("sign", sign)

			router.Method(http.MethodGet,
				"/get",
				http.HandlerFunc(proxyHandler))

			w, b := commons.HTTPDummyReq(router,
				http.MethodGet,
				fmt.Sprintf("/get?_verify=%s", url.QueryEscape(sign)),
				nil,
				nil)
			Expect(w.Code).To(Equal(http.StatusOK))

			log.Println("RAW", w.Code, string(b))

			By("Unsign payload and check salt ok")
		})
	})

	Context("Unsign payload and check from header", func() {
		It("Prepare", func() {

			opts := authorizer.Options{
				PrivateKey: privKeyStr,
				PublicKey:  pubKeyStr,
				TokenSource: authorizer.TokenSource{
					HeaderKey: "X-AuthVerify-UUID",
				},
				Expiry: 1400,
			}
			verifier = authorizer.NewVerifierService(&opts)
			Expect(verifier).NotTo(BeNil())

			claims := &authorizer.AuthClaims{
				StandardClaims: jwt.StandardClaims{
					Audience:  "ci-verifier-aud",
					Id:        uuid.New().String(),
					Issuer:    "ci-test",
					Subject:   salt,                                                     // salt
					ExpiresAt: time.Now().Add(time.Duration(3600) * time.Minute).Unix(), // expiry
				},
				MetaInfo: map[string]interface{}{
					"more": fake.Sentences(),
				},
			}

			// handler
			proxyHandler := func(w http.ResponseWriter, r *http.Request) {
				// check jwt
				res, err := verifier.UnSign(r)
				if err != nil {
					render.Status(r, http.StatusInternalServerError)
					render.JSON(w, r,
						err.Error(),
					)
					return
				}
				log.Printf("RES:%#v\n", res)
				oks := res.CheckSubject(salt)
				commons.JSONify("check salt", res, oks)
				if !oks {
					render.Status(r, http.StatusInternalServerError)
					render.JSON(w, r,
						err.Error(),
					)
					return
				}
			}

			// sign
			sign, err := verifier.Sign(claims)
			commons.JSONify(sign, err)
			Expect(len(sign)).Should(BeNumerically(">", 0))
			Expect(err).To(BeNil())

			log.Println("sign", sign)

			router.Method(http.MethodGet,
				"/get",
				http.HandlerFunc(proxyHandler))

			w, b := commons.HTTPDummyReq(router,
				http.MethodGet,
				"/get",
				map[string]string{
					"X-AuthVerify-UUID": sign,
				},
				nil)
			Expect(w.Code).To(Equal(http.StatusOK))

			log.Println("RAW", w.Code, string(b))

			By("Unsign payload and check from header ok")
		})
	})

	Context("Unsign payload and check from bearer", func() {
		It("Prepare", func() {

			opts := authorizer.Options{
				PrivateKey: privKeyStr,
				PublicKey:  pubKeyStr,
				TokenSource: authorizer.TokenSource{
					AuthBearer: true,
				},
				Expiry: 1400,
			}
			verifier = authorizer.NewVerifierService(&opts)
			Expect(verifier).NotTo(BeNil())

			claims := &authorizer.AuthClaims{
				StandardClaims: jwt.StandardClaims{
					Audience:  "ci-verifier-aud",
					Id:        uuid.New().String(),
					Issuer:    "ci-test",
					Subject:   salt,                                                     // salt
					ExpiresAt: time.Now().Add(time.Duration(3600) * time.Minute).Unix(), // expiry
				},
				MetaInfo: map[string]interface{}{
					"more": fake.Sentences(),
				},
			}

			// handler
			proxyHandler := func(w http.ResponseWriter, r *http.Request) {
				// check jwt
				res, err := verifier.UnSign(r)
				if err != nil {
					render.Status(r, http.StatusInternalServerError)
					render.JSON(w, r,
						err.Error(),
					)
					return
				}
				log.Printf("RES:%#v\n", res)
				oks := res.CheckSubject(salt)
				commons.JSONify("check salt", res, oks)
				if !oks {
					render.Status(r, http.StatusInternalServerError)
					render.JSON(w, r,
						err.Error(),
					)
					return
				}
			}

			// sign
			sign, err := verifier.Sign(claims)
			commons.JSONify(sign, err)
			Expect(len(sign)).Should(BeNumerically(">", 0))
			Expect(err).To(BeNil())

			log.Println("sign", sign)

			router.Method(http.MethodGet,
				"/get",
				http.HandlerFunc(proxyHandler))

			w, b := commons.HTTPDummyReq(router,
				http.MethodGet,
				"/get",
				map[string]string{
					"Authorization": fmt.Sprintf("Bearer %s", sign),
				},
				nil)
			Expect(w.Code).To(Equal(http.StatusOK))

			log.Println("RAW", w.Code, string(b))

			By("Unsign payload and check from bearer ok")
		})
	})

	Context("Unsign payload and check from bearer empty", func() {
		It("Prepare", func() {

			opts := authorizer.Options{
				PrivateKey: privKeyStr,
				PublicKey:  pubKeyStr,
				TokenSource: authorizer.TokenSource{
					AuthBearer: true,
				},
				Expiry: 1400,
			}
			verifier = authorizer.NewVerifierService(&opts)
			Expect(verifier).NotTo(BeNil())

			claims := &authorizer.AuthClaims{
				StandardClaims: jwt.StandardClaims{
					Audience:  "ci-verifier-aud",
					Id:        uuid.New().String(),
					Issuer:    "ci-test",
					Subject:   salt,                                                     // salt
					ExpiresAt: time.Now().Add(time.Duration(3600) * time.Minute).Unix(), // expiry
				},
				MetaInfo: map[string]interface{}{
					"more": fake.Sentences(),
				},
			}

			// handler
			proxyHandler := func(w http.ResponseWriter, r *http.Request) {
				// check jwt
				res, err := verifier.UnSign(r)
				if err != nil {
					render.Status(r, http.StatusInternalServerError)
					render.JSON(w, r,
						err.Error(),
					)
					return
				}
				log.Printf("RES:%#v\n", res)

			}

			// sign
			sign, err := verifier.Sign(claims)
			commons.JSONify(sign, err)
			Expect(len(sign)).Should(BeNumerically(">", 0))
			Expect(err).To(BeNil())

			log.Println("sign", sign)

			router.Method(http.MethodGet,
				"/get",
				http.HandlerFunc(proxyHandler))

			w, b := commons.HTTPDummyReq(router,
				http.MethodGet,
				"/get",
				map[string]string{
					"Authorization": fmt.Sprintf("XBearer %s", sign),
				},
				nil)
			Expect(w.Code).NotTo(Equal(http.StatusOK))

			log.Println("RAW", w.Code, string(b))

			By("Unsign payload and check from bearer empty ok")
		})
	})

	Context("Generic", func() {
		It("Prepare", func() {

			opts := authorizer.Options{
				PrivateKey: privKeyStr,
				PublicKey:  pubKeyStr,
				TokenSource: authorizer.TokenSource{
					QueryKey: "_verify",
				},
			}
			verifier = authorizer.NewVerifierService(&opts)
			Expect(verifier).NotTo(BeNil())

			// sign not ok
			sign, err := verifier.Sign(nil)
			commons.JSONify(sign, err)
			Expect(len(sign)).Should(BeNumerically("<=", 0))
			Expect(err).NotTo(BeNil())

			claims := &authorizer.AuthClaims{
				StandardClaims: jwt.StandardClaims{
					Audience: "ci-verifier-aud",
					Id:       uuid.New().String(),
					Issuer:   "ci-test",
					Subject:  salt, // salt
				},
				MetaInfo: map[string]interface{}{},
			}

			// sign ok
			sign, err = verifier.Sign(claims)
			commons.JSONify(sign, err)
			Expect(len(sign)).Should(BeNumerically(">", 0))
			Expect(err).To(BeNil())

			By("Generic ok")
		})
	})
})
