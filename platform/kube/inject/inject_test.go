// Copyright 2017 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package inject

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"github.com/pmezard/go-difflib/difflib"
)

func TestImageName(t *testing.T) {
	want := "docker.io/istio/init:latest"
	if got := InitImageName("docker.io/istio", "latest"); got != want {
		t.Errorf("InitImageName() failed: got %q want %q", got, want)
	}
	want = "docker.io/istio/proxy:latest"
	if got := ProxyImageName("docker.io/istio", "latest"); got != want {
		t.Errorf("ProxyImageName() failed: got %q want %q", got, want)
	}
}

// Tag name should be kept in sync with value in platform/kube/inject/refresh.sh
const unitTestTag = "unittest"

func TestIntoResourceFile(t *testing.T) {

	cases := []struct {
		authConfigPath string
		enableAuth     bool
		in             string
		want           string
		enableCoreDump bool
	}{
		{
			in:   "testdata/hello.yaml",
			want: "testdata/hello.yaml.injected",
		},
		{
			in:   "testdata/frontend.yaml",
			want: "testdata/frontend.yaml.injected",
		},
		{
			in:   "testdata/hello-service.yaml",
			want: "testdata/hello-service.yaml.injected",
		},
		{
			in:   "testdata/hello-multi.yaml",
			want: "testdata/hello-multi.yaml.injected",
		},
		{
			in:   "testdata/hello.yaml.injected",
			want: "testdata/hello.yaml.injected",
		},
		{
			in:   "testdata/hello-ignore.yaml",
			want: "testdata/hello-ignore.yaml.injected",
		},
		{
			in:   "testdata/multi-init.yaml",
			want: "testdata/multi-init.yaml.injected",
		},
		{
			in:             "testdata/enable-core-dump.yaml",
			want:           "testdata/enable-core-dump.yaml.injected",
			enableCoreDump: true,
		},
		{
			enableAuth:     true,
			authConfigPath: "/etc/certs/",
			in:             "testdata/auth.yaml",
			want:           "testdata/auth.yaml.injected",
		},
		{
			enableAuth:     true,
			authConfigPath: "/etc/certs/",
			in:             "testdata/auth.non-default-service-account.yaml",
			want:           "testdata/auth.non-default-service-account.yaml.injected",
		},
		{
			enableAuth:     true,
			authConfigPath: "/etc/non-default-dir/",
			in:             "testdata/auth.yaml",
			want:           "testdata/auth.cert-dir.yaml.injected",
		},
	}

	for _, c := range cases {
		params := Params{
			InitImage:        InitImageName(DefaultHub, unitTestTag),
			ProxyImage:       ProxyImageName(DefaultHub, unitTestTag),
			Verbosity:        DefaultVerbosity,
			ManagerAddr:      DefaultManagerAddr,
			MixerAddr:        DefaultMixerAddr,
			SidecarProxyUID:  DefaultSidecarProxyUID,
			SidecarProxyPort: DefaultSidecarProxyPort,
			Version:          "12345678",
			EnableCoreDump:   c.enableCoreDump,
			EnableAuth:       c.enableAuth,
			AuthConfigPath:   c.authConfigPath,
		}
		in, err := os.Open(c.in)
		if err != nil {
			t.Fatalf("Failed to open %q: %v", c.in, err)
		}
		defer func() { _ = in.Close() }()
		var got bytes.Buffer
		if err = IntoResourceFile(&params, in, &got); err != nil {
			t.Fatalf("IntoResourceFile(%v) returned an error: %v", c.in, err)
		}
		want, err := ioutil.ReadFile(c.want)
		if err != nil {
			t.Fatalf("Failed to read %q: %v", c.want, err)
		}
		gotS, wantS := got.String(), string(want)
		if gotS != wantS {
			diff := difflib.UnifiedDiff{
				A:        difflib.SplitLines(gotS),
				B:        difflib.SplitLines(wantS),
				FromFile: "Got",
				ToFile:   "Want",
				Context:  2,
			}
			text, _ := difflib.GetUnifiedDiffString(diff)
			t.Errorf("IntoResourceFile(%v) failed:\n%v", c.in, text)
		}
	}

	// file with mixture of deployment, service, etc.
	// file with existing annotation
	// file with another init-container
}
