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

package test

import (
	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/log"
	"math/big"
	"testing"
)

func TestQRProof(t *testing.T) {
	log.TurnOff() // otherwise too many communication messages
	dlog := config.LoadDLog("pseudonymsys")
	y1 := common.GetRandomInt(dlog.P)

	qrClient, err := client.NewQRClient(testGrpcClientConn, dlog, y1)
	if err != nil {
		t.Errorf("Error when initializing NewQRClient")
	}

	proved, err := qrClient.Run()
	if err != nil {
		t.Errorf("Error when proving y is QR")
	}

	assert.Equal(t, proved, true, "QR proof does not work correctly")
}

func TestQNRProof(t *testing.T) {
	log.TurnOff() // otherwise too many communication messages
	qr := config.LoadQR("qrsmall")
	y, _ := new(big.Int).SetString("12104178836609367680573806127379667907452906068454411069540554013287299560619180831355030260792398116234585889489580787593876656468666620239704236202828625502145041222925221901747074982936094534863675673392263672910937547483238701395223837362913804135100562910313510524388491518118503153440479519531614792845582743827952578371105856240886035300256188119597496494955532842085616018276731618147827132295654573847443973865791627336995666490060797108039052526091724109438973877494599020695354285996982775389058505616271009101591441286538176405813622092518363027538767195421845003207037113604997900115835538908295151715618", 10)

	qnrClient, err := client.NewQNRClient(testGrpcClientConn, qr, y)
	if err != nil {
		t.Errorf("Error when initializing NewQNRClient")
	}

	proved, err := qnrClient.Run()
	if err != nil {
		t.Errorf("Error when proving y is QNR")
	}

	assert.Equal(t, proved, true, "QNR proof does not work correctly")
}
