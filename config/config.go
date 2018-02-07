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

	"os"
	"path/filepath"

	"github.com/spf13/viper"
	"github.com/xlab-si/emmy/crypto/groups"
)

// init loads the default config file
func init() {
	// set reasonable defaults
	setDefaults()

	// override defaults with configuration read from configuration file
	viper.AddConfigPath("$GOPATH/src/github.com/xlab-si/emmy/config")
	err := loadConfig("defaults", "yml")
	if err != nil {
		fmt.Println(err)
	}
}

// setDefaults sets default values for various parts of emmy library.
func setDefaults() {
	viper.SetDefault("ip", "localhost")
	viper.SetDefault("port", 7007)
	viper.SetDefault("timeout", 5000)
	viper.SetDefault("key_folder", "/tmp")

	p := "16714772973240639959372252262788596420406994288943442724185217359247384753656472309049760952976644136858333233015922583099687128195321947212684779063190875332970679291085543110146729439665070418750765330192961290161474133279960593149307037455272278582955789954847238104228800942225108143276152223829168166008095539967222363070565697796008563529948374781419181195126018918350805639881625937503224895840081959848677868603567824611344898153185576740445411565094067875133968946677861528581074542082733743513314354002186235230287355796577107626422168586230066573268163712626444511811717579062108697723640288393001520781671"
	g := "13435884250597730820988673213378477726569723275417649800394889054421903151074346851880546685189913185057745735207225301201852559405644051816872014272331570072588339952516472247887067226166870605704408444976351128304008060633104261817510492686675023829741899954314711345836179919335915048014505501663400445038922206852759960184725596503593479528001139942112019453197903890937374833630960726290426188275709258277826157649744326468681842975049888851018287222105796254410594654201885455104992968766625052811929321868035475972753772676518635683328238658266898993508045858598874318887564488464648635977972724303652243855656"
	q := "98208916160055856584884864196345443685461747768186057136819930381973920107591"

	pgq := map[string]string{
		"p": p,
		"g": g,
		"q": q,
	}

	viper.SetDefault("pedersen", pgq)
	viper.SetDefault("schnorr", pgq)

	pseudonymSysConfig := map[string]interface{}{
		"p":     p,
		"g":     g,
		"q":     q,
		"user1": "10501840420714326611674814933629820564884994433464121609699657686381725481917946560951300989428757857663890749444810669658158959171443678666294156633031855300155147813954782039163197859065107569638424682758546743970421679581497316473363590677852615245790857416631205041294470157319811083478928657427332727532272060990285330797695681228920548209293494826378319240408357619741465896984159808329187249915415180748872721286083954030337580803742552856969769146625693488160927221403705265205532491725454404938155197720048433342625635727130205282673205600167729513490481034307616261949529737060447713783467988717455504863857",
		"org1": map[string]string{
			"h1": "11253748020267515701977135421640400742511414782332660443524776235731592618314865082641495270379529602832564697632543178140373575666207325449816651443326295587329200580969897900340682863137274403743213121482058992744156278265298975875832815615008349379091580640663544863825594755871212120449589876097254391036951735135790415340694042060640287135597503154554767593490141558733646631257590898412097094878970047567251318564175378758713497120310233239160479122314980866111775954564694480706227862890375180173977176588970220883117212300621045744043530072238840577201003052170999723878986905807102656657527667244456412473985",
			"h2": "76168773256070905782197510623595125058465077612447809025568517977679494145178174622864958684725961070073576803345724904501942931513809178875449022568661712955904784104680061168715431907736821341951579763867969478146743783132963349845621343504647834967006527983684679901491401571352045358450346417143743546169924539113192750473927517206655311791719866371386836092309758541857984471638917674114075906273800379335165008797874367104743232737728633294061064784890416168238586934819945486226202990710177343797354424869474259809902990704930592533690341526792158132580375587182781640673464871125845158432761445006356929132",
			"s1": "12506074624757438676805734108203754691894440935285828326752482161724637860737614838944853691950924021955680525939780169779888653151633785040698255721224889673095292103687696155341406413918220576785413168329472933244872017244493792250782071009945084029853097333491235700618768793380791519193695496653451014859995982030252835982728985237780700293860028372794252498821615457701308171489000104682637461824347934289263165371702030406332522768141151117618446117035451332086067049461921041400592944133730824346746397649572514314171499080783864209863802530233234409464167893803459953492866757869441725196031561816682693694247",
			"s2": "130203329326872103700165538490407573774885754016819320468128775954825516",
		},
		"ca": map[string]string{
			"d":  "16249832937458088685598605121372353939294367897674422016342660883663371677076",
			"x":  "65326558506481070730591115387915499623679021660430456972125964980023301473231",
			"y1": "37526396936964061204061100652712760357856013823850948443144488667237183893571",
		},
	}
	viper.SetDefault("pseudonymsys", pseudonymSysConfig)
}

// loadConfig reads in the config file with configName being the name of the file (without suffix)
// and configType being "yml" or "json".
func loadConfig(configName string, configType string) error {
	viper.SetConfigName(configName)
	viper.SetConfigType(configType)

	err := viper.ReadInConfig()
	if err != nil {
		return fmt.Errorf("cannot read configuration file: %s\n", err)
	}

	return nil
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
func LoadTimeout() int {
	return viper.GetInt("timeout")
}

func LoadKeyDirFromConfig() string {
	key_path := viper.GetString("key_folder")
	return key_path
}

func LoadTestdataDir() string {
	prefix := filepath.Join(os.Getenv("GOPATH"), "src", "github.com", "xlab-si", "emmy")
	return filepath.Join(prefix, viper.GetString("testdata_dir"))
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
		panic(fmt.Errorf("error when loading QRRSA RSA group: %s\n", err))
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
