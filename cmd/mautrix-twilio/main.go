package main

import (
	"maunium.net/go/mautrix/bridgev2/matrix/mxmain"

	"go.mau.fi/mautrix-twilio/pkg/connector"
)

// Information to find out exactly which commit the bridge was built from.
// These are filled at build time with the -X linker flag.
var (
	Tag       = "unknown"
	Commit    = "unknown"
	BuildTime = "unknown"
)

func main() {
	m := mxmain.BridgeMain{
		Name:        "mautrix-twilio",
		Description: "A Matrix-Twilio bridge",
		URL:         "https://github.com/mautrix/twilio",
		Version:     "0.1.0",
		Connector:   &connector.TwilioConnector{},
	}
	m.InitVersion(Tag, Commit, BuildTime)
	m.Run()
}
