/*
 * Copyright 2017 XLAB d.o.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package config

import (
	"fmt"
	"math/big"

	"github.com/spf13/viper"
	"github.com/xlab-si/emmy/crypto/groups"
)

// init loads the default config file
func init() {
	viper.AddConfigPath("$GOPATH/src/github.com/xlab-si/emmy/config")
	LoadConfig("defaults", "yml")
}

// LoadConfig reads in the config file with configName being the name of the file (without suffix)
// and configType being "yml" or "json".
func LoadConfig(configName string, configType string) {
	viper.SetConfigName(configName)
	viper.SetConfigType(configType)

	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Cannot read configuration file: %s\n", err))
	}
}

// LoadServerPort returns the port where emmy server will be listening.
func LoadServerPort() int {
	return viper.GetInt("port")
}

// LoadServerEndpoint returns the endpoint of the emmy server where clients will be contacting it.
func LoadServerEndpoint() string {
	ip := viper.GetString("ip")
	port := LoadServerPort()
	return fmt.Sprintf("%v:%v", ip, port)
}

// LoadTimeout returns the specified number of seconds that clients wait before giving up
// on connection to emmy server
func LoadTimeout() float64 {
	return viper.GetFloat64("timeout")
}

func LoadKeyDirFromConfig() string {
	key_path := viper.GetString("key_folder")
	return key_path
}

func LoadTestdataDir() string {
	return viper.GetString("testdata_dir")
}

func LoadTestKeyDirFromConfig() string {
	key_path := viper.GetString("key_folder")
	return key_path
}

func LoadGroup(scheme string) *groups.SchnorrGroup {
	groupMap := viper.GetStringMap(scheme)
	p, _ := new(big.Int).SetString(groupMap["p"].(string), 10)
	g, _ := new(big.Int).SetString(groupMap["g"].(string), 10)
	q, _ := new(big.Int).SetString(groupMap["q"].(string), 10)
	return groups.NewSchnorrGroupFromParams(p, g, q)
}

func LoadQRRSA(name string) *groups.QRRSA {
	x := viper.GetStringMap(name)
	p, _ := new(big.Int).SetString(x["p"].(string), 10)
	q, _ := new(big.Int).SetString(x["q"].(string), 10)
	qr, err := groups.NewQRRSA(p, q)
	if err != nil {
		panic(fmt.Errorf("Error when loading QRRSA RSA group: %s\n", err))
	}
	return qr
}

func LoadPseudonymsysOrgSecrets(orgName, dlogType string) (*big.Int, *big.Int) {
	org := viper.GetStringMap(fmt.Sprintf("pseudonymsys.%s.%s", orgName, dlogType))
	s1, _ := new(big.Int).SetString(org["s1"].(string), 10)
	s2, _ := new(big.Int).SetString(org["s2"].(string), 10)
	return s1, s2
}

func LoadPseudonymsysOrgPubKeys(orgName string) (*big.Int, *big.Int) {
	org := viper.GetStringMap(fmt.Sprintf("pseudonymsys.%s.%s", orgName, "dlog"))
	h1, _ := new(big.Int).SetString(org["h1"].(string), 10)
	h2, _ := new(big.Int).SetString(org["h2"].(string), 10)
	return h1, h2
}

func LoadPseudonymsysOrgPubKeysEC(orgName string) (*big.Int, *big.Int, *big.Int, *big.Int) {
	org := viper.GetStringMap(fmt.Sprintf("pseudonymsys.%s.%s", orgName, "ecdlog"))
	h1X, _ := new(big.Int).SetString(org["h1x"].(string), 10)
	h1Y, _ := new(big.Int).SetString(org["h1y"].(string), 10)
	h2X, _ := new(big.Int).SetString(org["h2x"].(string), 10)
	h2Y, _ := new(big.Int).SetString(org["h2y"].(string), 10)
	return h1X, h1Y, h2X, h2Y
}

func LoadPseudonymsysCASecret() *big.Int {
	ca := viper.GetStringMap("pseudonymsys.ca")
	s, _ := new(big.Int).SetString(ca["d"].(string), 10)
	return s
}

func LoadPseudonymsysCAPubKey() (*big.Int, *big.Int) {
	ca := viper.GetStringMap("pseudonymsys.ca")
	x, _ := new(big.Int).SetString(ca["x"].(string), 10)
	y, _ := new(big.Int).SetString(ca["y1"].(string), 10)
	return x, y
}

func LoadServiceInfo() (string, string, string) {
	serviceName := viper.GetString("service_info.name")
	serviceProvider := viper.GetString("service_info.provider")
	serviceDescription := viper.GetString("service_info.description")
	return serviceName, serviceProvider, serviceDescription
}

func LoadSessionKeyMinByteLen() int {
	return viper.GetInt("session_key_bytelen")
}

func LoadRegistrationDBAddress() string {
	return viper.GetString("registration_db_address")
}
