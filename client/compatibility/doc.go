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

// Package compatibility implements wrapper types, constants and functions around
// github.com/xlab-si/emmy/client, making relevant functionality compatible with go language
// binding tools. All the constructs defined in this package are compatible with gobind tool that
// generates language bindings for Java or Objective C in order to expose Go code to Android or
// iOS mobile applications.
//
// The gobind tool imposes several restrictions on the types of exported fields,
// function parameters and their return values.
// Read more about them here: https://godoc.org/golang.org/x/mobile/cmd/gobind.
//
// Only Java bindings generated from this package were tested.
//
// Generating language bindings
//
// To generate Java bindings for use in an Android application,
// read the overview of gomobile tool (https://godoc.org/golang.org/x/mobile/cmd/gomobile).
// When you are all set, run:
// 	gomobile bind -v -o emmy.aar github.com/xlab-si/emmy/client/compatibility
// This command will produce an Android archive (.
// AAR) named emmy.aar from compatibility package.
// You can add generated AAR as a dependency to your Android application.
// Then, you can import Go types,
// functions and constants as regular Java types from the Java package compatibility. For instance,
// see Java code snippet below:
//	import compatibility.Connetion;
//	import compatibility.ConnectionConfig;
//	...
//	ConnectionConfig cfg = new ConnectionConfig("localhost:7007", "", cert.getBytes());
//	Connection conn = new Connection(cfg)
//
// Go types exposed to Java code
//
// Generic types:
//	ConnectionConfig
//	Connection
//	Logger
//	ServiceInfo
//
// Clients that allow us to execute various interactive cryptographic protocols with the server:
//	PseudonymsysCAClient
//	PseudonymsysClient
//	PseudonymsysCAECClient
//	PseudonymsysECClient
//
// Cryptographic types:
//	CACertificate
//	CACertificateEC
//	Credential
//	CredentialEC
//	ECGroupElement
//	PubKey
//	PubKeyEC
//	Transcript
//	TranscriptEC
// 	Pseudonym
// 	PseudonymEC
package compatibility
