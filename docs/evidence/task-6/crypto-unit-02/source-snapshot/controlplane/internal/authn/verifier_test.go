package authn

import (
    "context"
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "io"
    "math/big"
    "net/http"
    "net/http/httptest"
    "net/url"
    "strings"
    "sync"
    "sync/atomic"
    "testing"
    "time"
)

const testIssuer = "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/v2.0"
const testAudience = "22222222-2222-4222-8222-222222222222"
const testJWKS = "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/discovery/v2.0/keys"

var ephemeralKeys = sync.OnceValue(func() []*rsa.PrivateKey {
    keys := make([]*rsa.PrivateKey, 2)
    for i := range keys {
        var err error
        keys[i], err = rsa.GenerateKey(rand.Reader, 2048)
        if err != nil { panic("ephemeral RSA generation failed") }
    }
    return keys
})

type testClock struct { mu sync.Mutex; value time.Time }
func (c *testClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.value }
func (c *testClock) Advance(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.value = c.value.Add(d) }
type roundTripFunc func(*http.Request) (*http.Response, error)
func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type fixture struct {
    v *Verifier
    clock *testClock
    mu sync.Mutex
    body string
    status int
    calls atomic.Int64
    serve func(http.ResponseWriter, *http.Request)
}
func jwk(key *rsa.PrivateKey, kid string) map[string]any {
    return map[string]any{"kty":"RSA", "kid":kid, "use":"sig", "alg":"RS256", "key_ops":[]string{"verify"},
        "n":base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
        "e":base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}
}
func encoded(v any) string { b, err := json.Marshal(v); if err != nil { panic("fixture JSON failed") }; return string(b) }
func (f *fixture) setKeys(keys ...map[string]any) { f.setBody(encoded(map[string]any{"keys":keys}), 200) }
func (f *fixture) setBody(body string, status int) { f.mu.Lock(); defer f.mu.Unlock(); f.body, f.status = body, status }
func newFixture(t *testing.T) *fixture {
    t.Helper()
    f := &fixture{clock:&testClock{value:time.Unix(1800000000,0)}, status:200}
    f.setKeys(jwk(ephemeralKeys()[0], "A"))
    server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        f.calls.Add(1)
        f.mu.Lock(); body, status, custom := f.body, f.status, f.serve; f.mu.Unlock()
        if custom != nil { custom(w,r); return }
        w.WriteHeader(status); _, _ = io.WriteString(w, body)
    }))
    t.Cleanup(server.Close)
    target, _ := url.Parse(server.URL)
    transport := server.Client().Transport
    client := &http.Client{Timeout:3*time.Second, CheckRedirect:func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport:roundTripFunc(func(r *http.Request) (*http.Response,error) {
        if r.URL.String() != testJWKS { t.Error("request departed configured JWKS URL") }
        clone := r.Clone(r.Context()); address := *r.URL; address.Scheme, address.Host = target.Scheme, target.Host; clone.URL = &address
        return transport.RoundTrip(clone)
    })}
    var err error
    f.v, err = newVerifier(Config{Issuer:testIssuer, Audience:testAudience, JWKSURL:testJWKS}, client, f.clock.Now)
    if err != nil { t.Fatal("fixture verifier config rejected") }
    return f
}
func (f *fixture) claims() map[string]any {
    return map[string]any{"iss":testIssuer,"aud":testAudience,"sub":"local-user","exp":f.clock.Now().Add(time.Hour).Unix(),"nbf":f.clock.Now().Unix(),"ver":"2.0","scp":"warden.access"}
}
func signed(key *rsa.PrivateKey, header, claims string) string {
    raw := base64.RawURLEncoding.EncodeToString([]byte(header))+"."+base64.RawURLEncoding.EncodeToString([]byte(claims))
    sum := sha256.Sum256([]byte(raw)); sig, err := rsa.SignPKCS1v15(rand.Reader,key,crypto.SHA256,sum[:]); if err != nil { panic("fixture signing failed") }
    return raw+"."+base64.RawURLEncoding.EncodeToString(sig)
}
func token(f *fixture, index int, kid string) string {
    return signed(ephemeralKeys()[index],encoded(map[string]any{"alg":"RS256","typ":"JWT","kid":kid}),encoded(f.claims()))
}
func reject(t *testing.T, v *Verifier, raw string) {
    t.Helper(); if _, err := v.Verify(raw); err == nil { t.Fatal("untrusted token accepted") }
}
func accept(t *testing.T, v *Verifier, raw string) Claims {
    t.Helper(); c,err := v.Verify(raw); if err != nil { t.Fatal("valid scoped token rejected") }; return c
}

func TestVerify_RejectsWrongAudience(t *testing.T) {
    f:=newFixture(t)
    for _, aud := range []any{"other-resource","https://management.azure.com/","00000003-0000-0000-c000-000000000000",[]string{"other-resource"}} {
        c:=f.claims(); c["aud"]=aud
        reject(t,f.v,signed(ephemeralKeys()[0],`{"alg":"RS256","kid":"A"}`,encoded(c)))
    }
    if f.calls.Load()!=0 { t.Fatal("invalid audience triggered JWKS IO") }
}
func TestVerify_JWKSRotation(t *testing.T) {
    f:=newFixture(t); a:=token(f,0,"A"); accept(t,f.v,a)
    f.setKeys(jwk(ephemeralKeys()[0],"A"),jwk(ephemeralKeys()[1],"B"))
    b:=token(f,1,"B"); accept(t,f.v,b)
    if f.calls.Load()!=2 { t.Fatal("new kid did not refresh immediately") }
    f.setKeys(jwk(ephemeralKeys()[1],"B")); f.clock.Advance(10*time.Minute-time.Nanosecond); accept(t,f.v,a)
    if f.calls.Load()!=2 { t.Fatal("cache expired before exact TTL") }
    f.clock.Advance(time.Nanosecond); reject(t,f.v,a); accept(t,f.v,b)
    if f.calls.Load()!=3 { t.Fatal("expired snapshot was not atomically refreshed") }
}
func TestVerify_ClaimsAndSignatureBoundaries(t *testing.T) {
    f:=newFixture(t); valid:=token(f,0,"A"); c:=accept(t,f.v,valid)
    if c.Issuer!=testIssuer || c.Subject!="local-user" { t.Fatal("verified identity not returned") }
    changes:=map[string]func(map[string]any){
        "issuer":func(c map[string]any){ c["iss"]=testIssuer+"/" },
        "subject":func(c map[string]any){ c["sub"]="" },
        "expired":func(c map[string]any){ c["exp"]=f.clock.Now().Unix() },
        "missing-exp":func(c map[string]any){ delete(c,"exp") },
        "fractional-exp":func(c map[string]any){ c["exp"]=1800000000.5 },
        "string-exp":func(c map[string]any){ c["exp"]="1800003600" },
        "future-nbf":func(c map[string]any){ c["nbf"]=f.clock.Now().Add(time.Second).Unix() },
        "wrong-nbf-type":func(c map[string]any){ c["nbf"]=nil },
        "v1":func(c map[string]any){ c["ver"]="1.0" },
        "id-token":func(c map[string]any){ delete(c,"scp") },
        "app-token":func(c map[string]any){ delete(c,"scp"); c["roles"]=[]string{"warden.access"} },
        "wrong-scope":func(c map[string]any){ c["scp"]="warden.access.other" },
    }
    for name, change:=range changes { t.Run(name,func(t *testing.T){ c:=f.claims();change(c);reject(t,f.v,signed(ephemeralKeys()[0],`{"alg":"RS256","kid":"A"}`,encoded(c))) }) }
    c2:=f.claims();delete(c2,"nbf");c2["aud"]=[]string{testAudience,"other-resource"};c2["scp"]="profile warden.access"
    accept(t,f.v,signed(ephemeralKeys()[0],`{"alg":"RS256","kid":"A"}`,encoded(c2)))
    reject(t,f.v,signed(ephemeralKeys()[1],`{"alg":"RS256","kid":"A"}`,encoded(f.claims())))
    segments:=strings.Split(valid,".");segments[1]=base64.RawURLEncoding.EncodeToString([]byte(encoded(c2)));reject(t,f.v,strings.Join(segments,"."))
}
func TestVerify_RejectsAmbiguousOrMalformedJWT(t *testing.T) {
    f:=newFixture(t)
    for _, header:=range []string{`{"alg":"none","kid":"A"}`,`{"alg":"HS256","kid":"A"}`,`{"alg":"RS256","alg":"RS256","kid":"A"}`,`{"alg":"RS256","kid":"A","crit":["custom"]}`,`{"alg":"RS256","kid":"A","jku":"https://attacker.invalid/"}`,`{"alg":"RS256","kid":"A","x5u":"https://attacker.invalid/"}`,`{"alg":"RS256","kid":""}`,`{"alg":"RS256","kid":1}`,`{"alg":"RS256","kid":"`+strings.Repeat("a",129)+`"}`,`{"alg":"RS256","kid":"A","padding":"`+strings.Repeat("a",2048)+`"}`} {
        reject(t,f.v,signed(ephemeralKeys()[0],header,encoded(f.claims())))
    }
    claims:=encoded(f.claims());duplicate:=strings.TrimSuffix(claims,"}")+`,"sub":"second"}`
    reject(t,f.v,signed(ephemeralKeys()[0],`{"alg":"RS256","kid":"A"}`,duplicate))
    for _, raw:=range []string{"", "a.b", "a.b.c.d", ".a.b", "a..b", "a.b.", strings.Repeat("x",16385), "YWJj=.e30.AAAA", "e30.\ne30.AAAA"} { reject(t,f.v,raw) }
    if f.calls.Load()!=0 { t.Fatal("malformed JWT caused outbound IO") }
}
func TestVerify_JWKSRejectsUntrustedMaterial(t *testing.T) {
    changes:=map[string]func(map[string]any){
        "private":func(k map[string]any){ k["d"]="secret" },"secret-key":func(k map[string]any){k["k"]="secret"},
        "wrong-use":func(k map[string]any){k["use"]="enc"},"wrong-op":func(k map[string]any){k["key_ops"]=[]string{"sign"}},
        "wrong-alg":func(k map[string]any){k["alg"]="HS256"},"wrong-kty":func(k map[string]any){k["kty"]="EC"},
        "even-exponent":func(k map[string]any){k["e"]="Ag"},"huge-exponent":func(k map[string]any){k["e"]="f____w"},
        "small-modulus":func(k map[string]any){k["n"]="AQAB"},"oversize-modulus":func(k map[string]any){k["n"]=base64.RawURLEncoding.EncodeToString(append([]byte{0xff},make([]byte,512)...))},
        "noncanonical-modulus":func(k map[string]any){k["n"]=k["n"].(string)+"="},
    }
    for name,change:=range changes { t.Run(name,func(t *testing.T){f:=newFixture(t);k:=jwk(ephemeralKeys()[0],"A");change(k);f.setKeys(k);reject(t,f.v,token(f,0,"A"))}) }
    for name,body:=range map[string]string{
        "empty":`{"keys":[]}`,"duplicate-kid":encoded(map[string]any{"keys":[]any{jwk(ephemeralKeys()[0],"A"),jwk(ephemeralKeys()[1],"A")}}),
        "duplicate-json":`{"keys":[],"keys":[]}`,"trailing":`{"keys":[]} {}`,"oversize":strings.Repeat(" ",1048577),
    } {t.Run(name,func(t *testing.T){f:=newFixture(t);f.setBody(body,200);reject(t,f.v,token(f,0,"A"))})}
    t.Run("too-many-keys",func(t *testing.T){f:=newFixture(t);keys:=make([]map[string]any,65);for i:=range keys{keys[i]=jwk(ephemeralKeys()[0],strings.Repeat("x",i+1))};f.setKeys(keys...);reject(t,f.v,token(f,0,"A"))})
}
func TestVerify_FetchFailureNeverExtendsSnapshot(t *testing.T) {
    for _,status:=range []int{500,302,200} { t.Run(http.StatusText(status),func(t *testing.T){
        f:=newFixture(t);a:=token(f,0,"A");accept(t,f.v,a);f.setBody(`{"keys":[]}`,status)
        reject(t,f.v,token(f,1,"B"));accept(t,f.v,a)
        f.clock.Advance(10*time.Minute);reject(t,f.v,a);calls:=f.calls.Load();reject(t,f.v,a)
        if f.calls.Load()!=calls {t.Fatal("expired failure backoff ignored")}
        f.clock.Advance(time.Second);f.setKeys(jwk(ephemeralKeys()[1],"B"));reject(t,f.v,a);accept(t,f.v,token(f,1,"B"))
    }) }
}
func TestVerify_RefreshCoalescesAndCallerCancellationIsIsolated(t *testing.T) {
    f:=newFixture(t);accept(t,f.v,token(f,0,"A"))
    entered,release:=make(chan struct{},1),make(chan struct{});defer close(release)
    body:=encoded(map[string]any{"keys":[]any{jwk(ephemeralKeys()[1],"B")}})
    f.mu.Lock();f.serve=func(w http.ResponseWriter,r *http.Request){select{case entered<-struct{}{}:default:};select{case<-release:_,_=io.WriteString(w,body);case<-r.Context().Done():}};f.mu.Unlock()
    ctx,cancel:=context.WithCancel(context.Background());first:=make(chan error,1);go func(){_,err:=f.v.VerifyContext(ctx,token(f,1,"B"));first<-err}()
    select{case<-entered:case<-time.After(time.Second):t.Fatal("refresh did not start")}
    second:=make(chan error,1);go func(){_,err:=f.v.Verify(token(f,1,"B"));second<-err}()
    cancel();select{case err:=<-first:if err==nil{t.Fatal("canceled request accepted")};case<-time.After(time.Second):t.Fatal("cancellation blocked")}
    accept(t,f.v,token(f,0,"A"))
    // Changing the handler's release channel through this send keeps the defer's
    // close single-owned, while unblocking both verification callers.
    release<-struct{}{}
    select{case err:=<-second:if err!=nil{t.Fatal("one caller canceled shared refresh")};case<-time.After(time.Second):t.Fatal("shared caller blocked")}
    if f.calls.Load()!=2{t.Fatal("concurrent caller duplicated refresh")}
}
func TestVerify_UnknownKidPressureIsBounded(t *testing.T) {
    f:=newFixture(t);accept(t,f.v,token(f,0,"A"))
    for i:=1;i<=50;i++{reject(t,f.v,token(f,1,strings.Repeat("x",i)))}
    if f.calls.Load()!=3{t.Fatal("unknown-kid burst exceeded two new fetches")}
    accept(t,f.v,token(f,0,"A"));f.clock.Advance(500*time.Millisecond);f.setKeys(jwk(ephemeralKeys()[1],"B"));accept(t,f.v,token(f,1,"B"))
    if f.calls.Load()!=4{t.Fatal("refresh budget did not refill at two per second")}
}
func TestVerify_ConcurrentWaitersAreBounded(t *testing.T) {
    f:=newFixture(t);accept(t,f.v,token(f,0,"A"));ctx,cancel:=context.WithCancel(context.Background());defer cancel()
    entered:=make(chan struct{},1);f.mu.Lock();f.serve=func(w http.ResponseWriter,r *http.Request){select{case entered<-struct{}{}:default:};<-r.Context().Done()};f.mu.Unlock()
    results:=make(chan error,64);for i:=0;i<64;i++{go func(){_,err:=f.v.VerifyContext(ctx,token(f,1,"B"));results<-err}()}
    select{case<-entered:case<-time.After(time.Second):t.Fatal("no refresh")}
    // At least half must fail admission while the single refresh is blocked.
    for i:=0;i<32;i++{select{case err:=<-results:if err==nil{t.Fatal("unknown key accepted")};case<-time.After(time.Second):t.Fatal("waiter bound not enforced")}}
    if f.calls.Load()!=2{t.Fatal("waiters spawned extra network fetches")}
    cancel();for i:=0;i<32;i++{select{case<-results:case<-time.After(time.Second):t.Fatal("waiter cancellation stalled")}}
}
func TestVerify_BoundedFetchTimeoutAndCanceledInput(t *testing.T) {
    f:=newFixture(t)
    f.mu.Lock();f.serve=func(w http.ResponseWriter,r *http.Request){<-r.Context().Done()};f.mu.Unlock()
    ctx,cancel:=context.WithCancel(context.Background());cancel();_,err:=f.v.VerifyContext(ctx,token(f,0,"A"));if err==nil{t.Fatal("canceled input accepted")}
    if f.calls.Load()!=0{t.Fatal("already canceled request fetched")}
    start:=time.Now();reject(t,f.v,token(f,0,"A"));if time.Since(start)>4*time.Second{t.Fatal("fetch exceeded bounded timeout")}
}
func TestVerifier_ProductionConfigFailsClosed(t *testing.T) {
    cfg:=Config{Issuer:testIssuer,Audience:testAudience,JWKSURL:testJWKS}
    if _,err:=New(cfg);err!=nil{t.Fatal("valid fixed authority rejected")}
    for _,change:=range []func(*Config){func(c *Config){c.Issuer=""},func(c *Config){c.Issuer="https://login.microsoftonline.com/common/v2.0"},func(c *Config){c.Issuer="https://login.microsoftonline.com/organizations/v2.0"},func(c *Config){c.Audience=""},func(c *Config){c.JWKSURL="http://localhost/keys"},func(c *Config){c.JWKSURL="https://attacker.invalid/keys"},func(c *Config){c.JWKSURL=testJWKS+"#fragment"},func(c *Config){c.JWKSURL="https://user:pass@login.microsoftonline.com/keys"}}{
        c:=cfg;change(&c);if _,err:=New(c);err==nil{t.Fatal("unsafe configuration accepted")}
    }
}

func TestVerify_DoesNotFollowRedirect(t *testing.T) {
    f:=newFixture(t)
    f.mu.Lock();f.serve=func(w http.ResponseWriter,r *http.Request){http.Redirect(w,r,testJWKS,http.StatusFound)};f.mu.Unlock()
    reject(t,f.v,token(f,0,"A"))
    if f.calls.Load()!=1{t.Fatal("JWKS redirect was followed")}
}

func TestVerify_RechecksTokenExpiryAfterFetch(t *testing.T) {
    f:=newFixture(t);raw:=token(f,0,"A")
    body:=encoded(map[string]any{"keys":[]any{jwk(ephemeralKeys()[0],"A")}})
    f.mu.Lock();f.serve=func(w http.ResponseWriter,r *http.Request){f.clock.Advance(time.Hour);_,_=io.WriteString(w,body)};f.mu.Unlock()
    reject(t,f.v,raw)
}

func TestVerify_InvalidJWKSDoesNotReplaceFreshKnownKeys(t *testing.T) {
    f:=newFixture(t);a:=token(f,0,"A");accept(t,f.v,a)
    k:=encoded(jwk(ephemeralKeys()[1],"B"));k=strings.TrimSuffix(k,"}")+`,"kid":"different"}`
    f.setBody(`{"keys":[`+k+`]}`,200)
    reject(t,f.v,token(f,1,"B"));accept(t,f.v,a)
    f.clock.Advance(10*time.Minute);reject(t,f.v,a)
}

func TestVerify_RejectsNoncanonicalBase64AndDuplicateEscapedNames(t *testing.T) {
    f:=newFixture(t)
    reject(t,f.v,signed(ephemeralKeys()[0],`{"alg":"RS256","\u0061lg":"RS256","kid":"A"}`,encoded(f.claims())))
    raw:=token(f,0,"A");alphabet:="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last:=strings.IndexByte(alphabet,raw[len(raw)-1]);raw=raw[:len(raw)-1]+string(alphabet[last+1])
    reject(t,f.v,raw)
    if f.calls.Load()!=0{t.Fatal("ambiguous token triggered network IO")}
}
