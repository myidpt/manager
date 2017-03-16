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

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	ghodss_yaml "github.com/ghodss/yaml"
	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/spf13/cobra"

	"istio.io/manager/cmd"
	"istio.io/manager/model"

	"k8s.io/client-go/pkg/api"
	meta_v1 "k8s.io/client-go/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/util/yaml"
)

// Each entry in the multi-doc YAML file used by `istioctl create -f` MUST have this format
type inputDoc struct {
	// Type SHOULD be one of the kinds in model.IstioConfig; a route-rule, ingress-rule, or destination-policy
	Type string      `json:"type,omitempty"`
	Name string      `json:"name,omitempty"`
	Spec interface{} `json:"spec,omitempty"`
	// ParsedSpec will be one of the messages in model.IstioConfig: for example an
	// istio.proxy.v1alpha.config.RouteRule or DestinationPolicy
	ParsedSpec proto.Message `json:"-"`
}

var (
	// input file name
	file string

	key    model.Key
	schema model.ProtoSchema

	extensionTypes = map[string]func(map[string]interface{}, inputDoc) error{"mixer-policy": mixerPolicyConverter}

	postCmd = &cobra.Command{
		Use:   "create",
		Short: "Create policies and rules",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) != 0 {
				return fmt.Errorf("create takes no arguments")
			}
			varr, err := readInputs()
			if err != nil {
				return err
			}
			if len(varr) == 0 {
				return errors.New("nothing to create")
			}
			mixerStatechange := false
			for _, v := range varr {
				if v.ParsedSpec != nil {
					if err = setup(v.Type, v.Name); err != nil {
						return err
					}
					err = cmd.Client.Post(key, v.ParsedSpec)
					if err != nil {
						return err
					}
					fmt.Printf("Posted %v %v\n", v.Type, v.Name)
				} else {
					mixerStatechange = true
				}
			}
			if mixerStatechange {
				// By convention, the mixer uses keys globalconfig.yml and serviceconfig.yml.
				// Currently we only support mixer-policy, which is part of globalconfig.yaml
				globalConfig, err := getConfigMapYamlFile("mixer-config", "globalconfig.yml")
				if err != nil {
					return err
				}
				// Merge each mixer-policy document with globalconfig.yaml
				for _, v := range varr {
					converterFunc, ok := extensionTypes[v.Type]
					if ok {
						if err = converterFunc(globalConfig, v); err != nil {
							return err
						}
					}
				}
				// Istio Mixer stores the globalConfig as a YAML string inside JSON, so serialize it
				newYaml, err := ghodss_yaml.Marshal(globalConfig)
				if err != nil {
					return err
				}
				// Now, wrap it in a jsonpatch.Patch object so that we can update just the globalconfig.yaml
				// without touching other Istio Mixer settings
				bytes, err := json.Marshal([]map[string]interface{}{{
					"op":    "replace",
					"path":  "/data/globalconfig.yml",
					"value": string(newYaml)}})
				if err != nil {
					return err
				}
				// Now actually PATCH it
				_, err = cmd.Client.GetKubernetesClient().CoreV1().ConfigMaps(cmd.RootFlags.Namespace).
					Patch("mixer-config", api.JSONPatchType, bytes)
				if err != nil {
					return err
				}
				fmt.Printf("Patched mixer-config\n")
			}

			return nil
		},
	}

	putCmd = &cobra.Command{
		Use:   "replace",
		Short: "Replace policies and rules",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) != 0 {
				return fmt.Errorf("replace takes no arguments")
			}
			varr, err := readInputs()
			if err != nil {
				return err
			}
			if len(varr) == 0 {
				return errors.New("nothing to replace")
			}
			for _, v := range varr {
				if v.ParsedSpec != nil {
					if err = setup(v.Type, v.Name); err != nil {
						return err
					}
					err = cmd.Client.Put(key, v.ParsedSpec)
					if err != nil {
						return err
					}
					fmt.Printf("Put %v %v\n", v.Type, v.Name)
				} else {
					// I am not sure how to patch, given that mixer policies are a list already
					return errors.New("Replacing mixer-policy unimplemented")
				}
			}

			return nil
		},
	}

	getCmd = &cobra.Command{
		Use:   "get <type> <name>",
		Short: "Retrieve a policy or rule",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) != 2 {
				return fmt.Errorf("provide configuration type and name")
			}
			if err := setup(args[0], args[1]); err != nil {
				return err
			}
			item, exists := cmd.Client.Get(key)
			if !exists {
				return fmt.Errorf("does not exist")
			}
			out, err := schema.ToYAML(item)
			if err != nil {
				return err
			}
			fmt.Print(out)
			return nil
		},
	}

	deleteCmd = &cobra.Command{
		Use:   "delete <type> <name> [<name2> ... <nameN>]",
		Short: "Delete policies or rules",
		RunE: func(c *cobra.Command, args []string) error {
			// If we did not receive a file option, get names of resources to delete from command line
			if file == "" {
				if len(args) < 2 {
					return fmt.Errorf("provide configuration type and name or -f option")
				}
				for i := 1; i < len(args); i++ {
					_, ok := extensionTypes[args[0]]
					if !ok {
						if err := setup(args[0], args[i]); err != nil {
							return err
						}
						if err := cmd.Client.Delete(key); err != nil {
							return err
						}
					} else {
						if err := deleteExtensionType(args[0], args[1]); err != nil {
							return err
						}
					}
					fmt.Printf("Deleted %v %v\n", args[0], args[i])
				}
				return nil
			}

			// As we did get a file option, make sure the command line did not include any resources to delete
			if len(args) != 0 {
				return fmt.Errorf("delete takes no arguments when the file option is used")
			}
			varr, err := readInputs()
			if err != nil {
				return err
			}
			if len(varr) == 0 {
				return errors.New("nothing to delete")
			}
			for _, v := range varr {
				_, ok := extensionTypes[v.Type]
				if !ok {
					if err = setup(v.Type, v.Name); err != nil {
						return err
					}
					err = cmd.Client.Delete(key)
					if err != nil {
						return err
					}
				} else {
					if err := deleteExtensionType(v.Type, v.Name); err != nil {
						return err
					}
				}
				fmt.Printf("Deleted %v %v\n", v.Type, v.Name)
			}

			return nil
		},
	}

	listCmd = &cobra.Command{
		Use:   "list <type>",
		Short: "List policies and rules",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("please specify configuration type (one of %v)", model.IstioConfig.Kinds())
			}
			if err := setup(args[0], ""); err != nil {
				return err
			}

			list, err := cmd.Client.List(key.Kind, key.Namespace)
			if err != nil {
				return fmt.Errorf("error listing %s: %v", key.Kind, err)
			}

			for key, item := range list {
				out, err := schema.ToYAML(item)
				if err != nil {
					fmt.Println(err)
				} else {
					fmt.Printf("kind: %s\n", key.Kind)
					fmt.Printf("name: %s\n", key.Name)
					fmt.Printf("namespace: %s\n", key.Namespace)
					fmt.Println("spec:")
					lines := strings.Split(out, "\n")
					for _, line := range lines {
						if line != "" {
							fmt.Printf("  %s\n", line)
						}
					}
				}
				fmt.Println("---")
			}
			return nil
		},
	}
)

func init() {
	postCmd.PersistentFlags().StringVarP(&file, "file", "f", "",
		"Input file with the content of the configuration objects (if not set, command reads from the standard input)")
	putCmd.PersistentFlags().AddFlag(postCmd.PersistentFlags().Lookup("file"))
	deleteCmd.PersistentFlags().AddFlag(postCmd.PersistentFlags().Lookup("file"))

	cmd.RootCmd.Use = "istioctl"
	cmd.RootCmd.Long = fmt.Sprintf("Istio configuration command line utility. Available configuration types: %v",
		model.IstioConfig.Kinds())
	cmd.RootCmd.AddCommand(postCmd)
	cmd.RootCmd.AddCommand(putCmd)
	cmd.RootCmd.AddCommand(getCmd)
	cmd.RootCmd.AddCommand(listCmd)
	cmd.RootCmd.AddCommand(deleteCmd)
}

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		glog.Error(err)
		os.Exit(-1)
	}
}

func setupNamespace() {
	// use default namespace by default
	if cmd.RootFlags.Namespace == "" {
		glog.V(2).Info(fmt.Sprintf("Using default namespace %v\n", api.NamespaceDefault))
		cmd.RootFlags.Namespace = api.NamespaceDefault
	}
}

func setup(kind, name string) error {
	var ok bool
	// set proto schema
	schema, ok = model.IstioConfig[kind]
	if !ok {
		return fmt.Errorf("unknown configuration type %s; use one of %v", kind, model.IstioConfig.Kinds())
	}

	setupNamespace()

	// set the config key
	key = model.Key{
		Kind:      kind,
		Name:      name,
		Namespace: cmd.RootFlags.Namespace,
	}

	return nil
}

// readInputs reads multiple documents from the input and checks with the schema
func readInputs() ([]inputDoc, error) {

	var reader io.Reader
	var err error

	if file == "" {
		reader = os.Stdin
	} else {
		reader, err = os.Open(file)
		if err != nil {
			return nil, err
		}
	}

	var varr []inputDoc

	// We store route-rules as a YaML stream; there may be more than one decoder.
	yamlDecoder := yaml.NewYAMLOrJSONDecoder(reader, 512*1024)
	for {
		v := inputDoc{}
		err = yamlDecoder.Decode(&v)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("cannot parse proto message: %v", err)
		}

		// Do a second decode pass, to get the data into structured format
		byteRule, err := json.Marshal(v.Spec)
		if err != nil {
			return nil, fmt.Errorf("could not encode Spec: %v", err)
		}

		schema, ok := model.IstioConfig[v.Type]
		if !ok {

			// If this is a "mixer-policy", there is no need to be able to get its schema from IstioConfig
			_, ok := extensionTypes[v.Type]
			if !ok {
				glog.Error(fmt.Sprintf("unknown spec type %s", v.Type))
				return nil, fmt.Errorf("unknown spec type %s", v.Type)
			}

			glog.V(2).Info(fmt.Sprintf("Encountered extended type %v %v", v.Type, v.Name))

		} else {

			rr, err := schema.FromJSON(string(byteRule))
			if err != nil {
				return nil, fmt.Errorf("cannot parse proto message: %v", err)
			}
			glog.V(2).Info(fmt.Sprintf("Parsed %v %v into %v %v", v.Type, v.Name, schema.MessageName, rr))

			v.ParsedSpec = rr
		}

		varr = append(varr, v)
	}

	return varr, nil
}

// Given an inputDoc, add to "adapters" key
// TODO Support for Replace and Delete?
func mixerPolicyConverter(accum map[string]interface{}, mixerPolicy inputDoc) error {

	mixerPolicySpec := mixerPolicy.Spec.(map[string]interface{})
	mixerPolicyRules := mixerPolicySpec["rules"]
	newAdapter := map[string]interface{}{"name": mixerPolicy.Type + "-" + mixerPolicy.Name,
		"kind":   "quotas",
		"impl":   "memQuota",
		"params": map[string]interface{}{"rules": []interface{}{mixerPolicyRules}},
	}
	adapters := accum["adapters"].([]interface{})

	// Verify no adapter by that name exists
	for _, elem := range adapters {
		if adapter, ok := elem.(map[string]interface{}); ok {
			if adapter["name"] == newAdapter["name"] {
				return fmt.Errorf("Mixer Policy %v already exists", mixerPolicy.Name)
			}
		}
	}

	accum["adapters"] = append(adapters, newAdapter)

	return nil
}

func deleteExtensionType(t string, name string) error {
	return fmt.Errorf("deleting an extension type unimplemented %v %v", t, name)
}

func getConfigMapYamlFile(name string, data string) (map[string]interface{}, error) {
	setupNamespace()
	configMap, err := cmd.Client.GetKubernetesClient().CoreV1().ConfigMaps(cmd.RootFlags.Namespace).
		Get(name, meta_v1.GetOptions{})
	if err != nil {
		return nil, err
	}
	yamlString, ok := configMap.Data[data]
	if !ok {
		return nil, fmt.Errorf("%v does not have %v", name, data)
	}

	yamlDecoder := yaml.NewYAMLOrJSONDecoder(strings.NewReader(yamlString), 512*1024)
	v := make(map[string]interface{}, 1)
	err = yamlDecoder.Decode(&v)
	if err != nil {
		return nil, err
	}
	return v, nil
}
