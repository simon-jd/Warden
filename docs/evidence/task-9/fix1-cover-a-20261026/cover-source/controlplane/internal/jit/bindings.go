package jit

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"warden/controlplane/internal/canonical"
)

var ErrBindingConflict = errors.New("JIT binding ownership or version conflict")

// KubernetesConfig is trusted deployment configuration. Transport must validate
// the cluster TLS certificate and must not follow redirects. No kubeconfig,
// host credentials, environment discovery or default transport is used here.
type KubernetesConfig struct {
	Endpoint string
	Transport http.RoundTripper
	BearerToken func(context.Context) (string, error)
}

type KubernetesBindings struct { config KubernetesConfig }

func NewKubernetesBindings(config KubernetesConfig) (*KubernetesBindings, error) {
	u, err := url.Parse(config.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") || config.Transport == nil || config.BearerToken == nil { return nil, ErrInvalid }
	config.Endpoint = strings.TrimSuffix(config.Endpoint, "/")
	return &KubernetesBindings{config: config}, nil
}

type subject struct {
	Kind string `json:"kind"`
	APIGroup string `json:"apiGroup"`
	Name string `json:"name"`
}

type roleReference struct {
	APIGroup string `json:"apiGroup"`
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type bindingObject struct {
	APIVersion string `json:"apiVersion"`
	Kind string `json:"kind"`
	Metadata map[string]json.RawMessage `json:"metadata"`
	Subjects []subject `json:"subjects"`
	RoleRef roleReference `json:"roleRef"`
}

const rbacAPI = "rbac.authorization.k8s.io"
const maxBindingBody = 65536
const revocationFence = "warden.io/revocation-fence"

func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

func validTarget(t Target) bool {
	return textID(t.TenantID, 256) && requestID(t.RequestID) && t.Name == "jit-"+strings.ToLower(t.RequestID) && dnsName(t.Namespace, 63) && !strings.Contains(t.Namespace, ".") && dnsName(t.Role, 253) && textID(t.User, 256) && !t.ExpiresAt.IsZero()
}

func ownedAnnotations(t Target) map[string]string {
	return map[string]string{"warden.io/tenant": t.TenantID, "warden.io/request": t.RequestID, "warden.io/expires-at": t.ExpiresAt.UTC().Format(time.RFC3339Nano), "warden.io/user": t.User}
}

func newBinding(t Target) bindingObject {
	return bindingObject{APIVersion: rbacAPI+"/v1", Kind: "RoleBinding", Metadata: map[string]json.RawMessage{"name": raw(t.Name), "namespace": raw(t.Namespace), "annotations": raw(ownedAnnotations(t))}, Subjects: []subject{}, RoleRef: roleReference{APIGroup: rbacAPI, Kind: "Role", Name: t.Role}}
}

func metaString(o bindingObject, key string) string {
	var value string
	_ = json.Unmarshal(o.Metadata[key], &value)
	return value
}

// Exact-key checks precede encoding/json's case-insensitive struct matching.
// canonical.JSON also rejects duplicate keys, invalid UTF-8 and trailing data.
func keys(data []byte, allowed ...string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || object == nil { return nil, ErrBindingConflict }
	for key := range object {
		ok := false
		for _, a := range allowed { if key == a { ok = true; break } }
		if !ok { return nil, ErrBindingConflict }
	}
	return object, nil
}

func decodeBinding(body []byte, t Target) (bindingObject, error) {
	var o bindingObject
	canonicalBody, err := canonical.JSON(body)
	if err != nil { return o, ErrBindingConflict }
	fields, err := keys(canonicalBody, "apiVersion", "kind", "metadata", "subjects", "roleRef")
	if err != nil { return o, err }
	if _, err = keys(fields["metadata"], "name", "namespace", "uid", "resourceVersion", "annotations", "labels", "creationTimestamp", "deletionTimestamp", "deletionGracePeriodSeconds", "generation", "managedFields", "finalizers", "ownerReferences", "selfLink"); err != nil { return o, err }
	if _, err = keys(fields["roleRef"], "apiGroup", "kind", "name"); err != nil { return o, err }
	var subjects []json.RawMessage
	if len(fields["subjects"]) != 0 { if err = json.Unmarshal(fields["subjects"], &subjects); err != nil { return o, ErrBindingConflict } }
	for _, s := range subjects { if _, err = keys(s, "kind", "apiGroup", "name"); err != nil { return o, err } }
	if err = json.Unmarshal(canonicalBody, &o); err != nil { return o, ErrBindingConflict }
	if o.APIVersion != rbacAPI+"/v1" || o.Kind != "RoleBinding" || metaString(o, "name") != t.Name || metaString(o, "namespace") != t.Namespace || o.RoleRef != (roleReference{APIGroup: rbacAPI, Kind: "Role", Name: t.Role}) || !textID(metaString(o, "uid"), 256) || !textID(metaString(o, "resourceVersion"), 256) { return o, ErrBindingConflict }
	var annotations map[string]string
	if err = json.Unmarshal(o.Metadata["annotations"], &annotations); err != nil { return o, ErrBindingConflict }
	for k, v := range ownedAnnotations(t) { if annotations[k] != v { return o, ErrBindingConflict } }
	if len(o.Subjects) > 1 || (len(o.Subjects) == 1 && o.Subjects[0] != (subject{Kind: "User", APIGroup: rbacAPI, Name: t.User})) { return o, ErrBindingConflict }
	return o, nil
}

func (k *KubernetesBindings) call(ctx context.Context, method string, t Target, collection bool, body any) ([]byte, int, error) {
	if k == nil || !validTarget(t) { return nil, 0, ErrInvalid }
	path := "/apis/"+rbacAPI+"/v1/namespaces/"+url.PathEscape(t.Namespace)+"/rolebindings"
	if !collection { path += "/"+url.PathEscape(t.Name) }
	var encoded []byte
	var err error
	if body != nil { encoded, err = json.Marshal(body); if err != nil { return nil, 0, err } }
	if len(encoded) > maxBindingBody { return nil, 0, ErrBindingConflict }
	token, err := k.config.BearerToken(ctx)
	if err != nil { return nil, 0, ErrUnavailable }
	if !textID(token, 16384) { return nil, 0, ErrUnavailable }
	req, err := http.NewRequestWithContext(ctx, method, k.config.Endpoint+path, bytes.NewReader(encoded))
	if err != nil { return nil, 0, err }
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil { req.Header.Set("Content-Type", "application/json") }
	// RoundTrip, rather than Client.Do, never follows redirects or redirects credentials.
	response, err := k.config.Transport.RoundTrip(req)
	if err != nil { if response != nil && response.Body != nil { response.Body.Close() }; return nil, 0, ErrUnavailable }
	if response == nil || response.Body == nil { return nil, 0, ErrUnavailable }
	defer response.Body.Close()
	b, err := io.ReadAll(io.LimitReader(response.Body, maxBindingBody+1))
	if err != nil || len(b) > maxBindingBody { return nil, response.StatusCode, ErrUnavailable }
	return b, response.StatusCode, nil
}

func receipt(o bindingObject) Receipt { return Receipt{UID: metaString(o, "uid"), ResourceVersion: metaString(o, "resourceVersion")} }

func (k *KubernetesBindings) Reserve(parent context.Context, t Target) (Receipt, error) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	b, status, err := k.call(ctx, http.MethodPost, t, true, newBinding(t))
	if err != nil { return Receipt{}, err }
	if status != http.StatusCreated { return Receipt{}, ErrBindingConflict }
	o, err := decodeBinding(b, t)
	if err != nil { return Receipt{}, err }
	if len(o.Subjects) != 0 || string(o.Metadata["deletionTimestamp"]) != "" && string(o.Metadata["deletionTimestamp"]) != "null" { return Receipt{}, ErrBindingConflict }
	return receipt(o), nil
}

func (k *KubernetesBindings) Activate(parent context.Context, t Target, r Receipt) error {
	if !textID(r.UID, 256) || !textID(r.ResourceVersion, 256) { return ErrInvalid }
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	o := newBinding(t)
	o.Metadata["uid"], o.Metadata["resourceVersion"] = raw(r.UID), raw(r.ResourceVersion)
	o.Subjects = []subject{{Kind: "User", APIGroup: rbacAPI, Name: t.User}}
	b, status, err := k.call(ctx, http.MethodPut, t, false, o)
	if err != nil { return err }
	// Never retry an ambiguous activation or accept create-on-update (201).
	if status != http.StatusOK { return ErrBindingConflict }
	confirmed, err := decodeBinding(b, t)
	if err != nil { return err }
	if metaString(confirmed, "uid") != r.UID || metaString(confirmed, "resourceVersion") == r.ResourceVersion || len(confirmed.Subjects) != 1 { return ErrBindingConflict }
	return nil
}

func (k *KubernetesBindings) Remove(parent context.Context, t Target, r Receipt) error {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	for attempt := 0; attempt < 3; attempt++ {
		b, status, err := k.call(ctx, http.MethodGet, t, false, nil)
		if err != nil { return err }
		if status == http.StatusNotFound { return nil }
		if status != http.StatusOK { return ErrBindingConflict }
		o, err := decodeBinding(b, t)
		if err != nil { return err }
		if r.UID != "" && r.UID != metaString(o, "uid") { return ErrBindingConflict }
		// An empty-to-empty PUT may preserve resourceVersion. Change a persisted
		// annotation on every clear attempt so even cleanup retries fence Activate.
		var annotations map[string]string
		if err = json.Unmarshal(o.Metadata["annotations"], &annotations); err != nil || annotations == nil { return ErrBindingConflict }
		var nonce [16]byte
		if _, err = rand.Read(nonce[:]); err != nil { return ErrUnavailable }
		fence := hex.EncodeToString(nonce[:])
		if fence == annotations[revocationFence] { return ErrUnavailable }
		annotations[revocationFence] = fence
		o.Metadata["annotations"] = raw(annotations)
		o.Subjects = []subject{}
		b, status, err = k.call(ctx, http.MethodPut, t, false, o)
		if err != nil { return err }
		if status == http.StatusConflict || status == http.StatusNotFound { continue }
		if status != http.StatusOK { return ErrBindingConflict }
		cleared, err := decodeBinding(b, t)
		if err != nil { return err }
		var persisted map[string]string
		if err = json.Unmarshal(cleared.Metadata["annotations"], &persisted); err != nil || persisted[revocationFence] != fence { return ErrBindingConflict }
		if metaString(cleared, "uid") != metaString(o, "uid") || metaString(cleared, "resourceVersion") == metaString(o, "resourceVersion") || len(cleared.Subjects) != 0 { return ErrBindingConflict }
		options := map[string]any{"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": map[string]string{"uid": metaString(cleared, "uid"), "resourceVersion": metaString(cleared, "resourceVersion")}}
		_, status, err = k.call(ctx, http.MethodDelete, t, false, options)
		if err != nil { return err }
		if status == http.StatusConflict { continue }
		if status != http.StatusOK && status != http.StatusAccepted && status != http.StatusNoContent && status != http.StatusNotFound { return ErrBindingConflict }
		_, status, err = k.call(ctx, http.MethodGet, t, false, nil)
		if err != nil { return err }
		if status == http.StatusNotFound { return nil }
		// Presence or an error is not a completed removal; retry through a
		// fresh ownership check, and retain durable revoke_pending meanwhile.
		if status != http.StatusOK { return ErrBindingConflict }
	}
	return ErrBindingConflict
}
