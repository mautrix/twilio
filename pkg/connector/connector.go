package connector

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/twilio/twilio-go"
	tclient "github.com/twilio/twilio-go/client"
	openapi "github.com/twilio/twilio-go/rest/api/v2010"
	"github.com/twilio/twilio-go/twiml"
	"go.mau.fi/util/configupgrade"
	"go.mau.fi/util/ptr"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
)

type TwilioConnector struct {
	br *bridgev2.Bridge
}

var _ bridgev2.NetworkConnector = (*TwilioConnector)(nil)

func (tc *TwilioConnector) Init(bridge *bridgev2.Bridge) {
	tc.br = bridge
}

func (tc *TwilioConnector) Start(ctx context.Context) error {
	server, ok := tc.br.Matrix.(bridgev2.MatrixConnectorWithServer)
	if !ok {
		return fmt.Errorf("matrix connector does not implement MatrixConnectorWithServer")
	} else if server.GetPublicAddress() == "" {
		return fmt.Errorf("public address of bridge not configured")
	}
	r := server.GetRouter().PathPrefix("/_twilio").Subrouter()
	r.HandleFunc("/{loginID}/receive", tc.ReceiveMessage).Methods(http.MethodPost)
	return nil
}

func (tc *TwilioConnector) ReceiveMessage(w http.ResponseWriter, r *http.Request) {
	// First make sure the signature header is present and that the request body is valid form data.
	sig := r.Header.Get("X-Twilio-Signature")
	if sig == "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Missing signature header\n"))
		return
	}

	params := make(map[string]string)
	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Failed to parse form data\n"))
		return
	}
	for key, value := range r.PostForm {
		params[key] = value[0]
	}

	// Get the user login based on the path. We need it to find the right token
	// to use for validating the request signature.
	loginID := mux.Vars(r)["loginID"]
	login := tc.br.GetCachedUserLoginByID(networkid.UserLoginID(loginID))
	if login == nil {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Unrecognized login ID in request path\n"))
		return
	}
	client := login.Client.(*TwilioClient)

	// Now that we have the client, validate the request.
	if !client.RequestValidator.Validate(client.GetWebhookURL(), params, sig) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Invalid signature\n"))
		return
	}

	// Pass the request to the client for handling. This is where everything actually happens.
	client.HandleWebhook(r.Context(), params)

	// We don't want to respond immediately, so just send a blank TwiML response.
	twimlResult, err := twiml.Messages(nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(twimlResult))
	}
}

func (tc *TwilioConnector) GetCapabilities() *bridgev2.NetworkGeneralCapabilities {
	return &bridgev2.NetworkGeneralCapabilities{}
}

func (tc *TwilioConnector) GetName() bridgev2.BridgeName {
	return bridgev2.BridgeName{
		DisplayName:      "Twilio",
		NetworkURL:       "https://twilio.com",
		NetworkIcon:      "mxc://maunium.net/FYuKJHaCrSeSpvBJfHwgYylP",
		NetworkID:        "twilio",
		BeeperBridgeType: "go.mau.fi/mautrix-twilio",
		DefaultPort:      29322,
	}
}

func (tc *TwilioConnector) GetConfig() (example string, data any, upgrader configupgrade.Upgrader) {
	return "", nil, nil
}

func (tc *TwilioConnector) LoadUserLogin(ctx context.Context, login *bridgev2.UserLogin) error {
	accountSID := login.Metadata.Extra["account_sid"].(string)
	authToken := login.Metadata.Extra["auth_token"].(string)
	restClient := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username:   accountSID,
		Password:   authToken,
		AccountSid: accountSID,
	})
	validator := tclient.NewRequestValidator(authToken)
	login.Client = &TwilioClient{
		UserLogin:        login,
		Twilio:           restClient,
		RequestValidator: validator,
	}
	return nil
}

type TwilioClient struct {
	UserLogin        *bridgev2.UserLogin
	Twilio           *twilio.RestClient
	RequestValidator tclient.RequestValidator
}

var _ bridgev2.NetworkAPI = (*TwilioClient)(nil)

func (tc *TwilioClient) Connect(ctx context.Context) error {
	phoneNumbers, err := tc.Twilio.Api.ListIncomingPhoneNumber(nil)
	if err != nil {
		return fmt.Errorf("failed to list phone numbers: %w", err)
	}
	numberInUse := tc.UserLogin.Metadata.Extra["phone"].(string)
	var numberFound bool
	for _, number := range phoneNumbers {
		if number.PhoneNumber != nil && *number.PhoneNumber == numberInUse {
			numberFound = true
			break
		}
	}
	if !numberFound {
		return fmt.Errorf("phone number %s not found on account", numberInUse)
	}
	return nil
}

func (tc *TwilioClient) Disconnect() {}

func (tc *TwilioClient) IsLoggedIn() bool {
	return true
}

func (tc *TwilioClient) LogoutRemote(ctx context.Context) {}

func (tc *TwilioClient) GetCapabilities(ctx context.Context, portal *bridgev2.Portal) *bridgev2.NetworkRoomCapabilities {
	return &bridgev2.NetworkRoomCapabilities{
		MaxTextLength: 1600,
	}
}

func makeUserID(e164Phone string) networkid.UserID {
	return networkid.UserID(strings.TrimLeft(e164Phone, "+"))
}

func makePortalID(e164Phone string) networkid.PortalID {
	return networkid.PortalID(strings.TrimLeft(e164Phone, "+"))
}

func makeUserLoginID(accountSID, phoneSID string) networkid.UserLoginID {
	return networkid.UserLoginID(fmt.Sprintf("%s:%s", accountSID, phoneSID))
}

func (tc *TwilioClient) IsThisUser(ctx context.Context, userID networkid.UserID) bool {
	phoneNum := tc.UserLogin.Metadata.Extra["phone"].(string)
	return makeUserID(phoneNum) == userID
}

func (tc *TwilioClient) GetChatInfo(ctx context.Context, portal *bridgev2.Portal) (*bridgev2.ChatInfo, error) {
	return &bridgev2.ChatInfo{
		Members: &bridgev2.ChatMemberList{
			IsFull: true,
			Members: []bridgev2.ChatMember{
				{
					EventSender: bridgev2.EventSender{
						IsFromMe: true,
						Sender:   makeUserID(tc.UserLogin.Metadata.Extra["phone"].(string)),
					},
					// This could be omitted, but leave it in to be explicit.
					Membership: event.MembershipJoin,
					// Make the user moderator, so they can adjust the room metadata if they want to.
					PowerLevel: 50,
				},
				{
					EventSender: bridgev2.EventSender{
						Sender: networkid.UserID(portal.ID),
					},
					Membership: event.MembershipJoin,
					PowerLevel: 50,
				},
			},
		},
	}, nil
}

func (tc *TwilioClient) GetUserInfo(ctx context.Context, ghost *bridgev2.Ghost) (*bridgev2.UserInfo, error) {
	return &bridgev2.UserInfo{
		Identifiers: []string{fmt.Sprintf("tel:+%s", ghost.ID)},
		Name:        ptr.Ptr(fmt.Sprintf("+%s", ghost.ID)),
	}, nil
}

func (tc *TwilioClient) GetWebhookURL() string {
	server := tc.UserLogin.Bridge.Matrix.(bridgev2.MatrixConnectorWithServer)
	return fmt.Sprintf("%s/_twilio/%s/receive", server.GetPublicAddress(), tc.UserLogin.ID)
}

func (tc *TwilioClient) HandleWebhook(ctx context.Context, params map[string]string) {
	tc.UserLogin.Bridge.QueueRemoteEvent(tc.UserLogin, &bridgev2.SimpleRemoteEvent[map[string]string]{
		Type: bridgev2.RemoteEventMessage,
		LogContext: func(c zerolog.Context) zerolog.Context {
			return c.
				Str("from", params["From"]).
				Str("message_id", params["MessageSid"])
		},
		PortalKey: networkid.PortalKey{
			ID:       makePortalID(params["From"]),
			Receiver: tc.UserLogin.ID,
		},
		Data:         params,
		CreatePortal: true,
		ID:           networkid.MessageID(params["MessageSid"]),
		Sender: bridgev2.EventSender{
			Sender: makeUserID(params["From"]),
		},
		Timestamp:          time.Now(),
		ConvertMessageFunc: tc.convertMessage,
	})
}

func (tc *TwilioClient) convertMessage(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, data map[string]string) (*bridgev2.ConvertedMessage, error) {
	return &bridgev2.ConvertedMessage{
		Parts: []*bridgev2.ConvertedMessagePart{{
			Type: event.EventMessage,
			Content: &event.MessageEventContent{
				MsgType: event.MsgText,
				Body:    data["Body"],
			},
		}},
	}, nil
}

func (tc *TwilioClient) HandleMatrixMessage(ctx context.Context, msg *bridgev2.MatrixMessage) (message *bridgev2.MatrixMessageResponse, err error) {
	resp, err := tc.Twilio.Api.CreateMessage(&openapi.CreateMessageParams{
		To:   ptr.Ptr(fmt.Sprintf("+%s", msg.Portal.ID)),
		From: ptr.Ptr(tc.UserLogin.Metadata.Extra["phone"].(string)),
		Body: ptr.Ptr(msg.Content.Body),
	})
	if err != nil {
		return nil, err
	}
	return &bridgev2.MatrixMessageResponse{
		DB: &database.Message{
			ID:       networkid.MessageID(*resp.Sid),
			SenderID: makeUserID(*resp.From),
		},
	}, nil
}

func (tc *TwilioConnector) GetLoginFlows() []bridgev2.LoginFlow {
	return []bridgev2.LoginFlow{{
		Name:        "Auth token",
		Description: "Log in with your Twilio account SID and auth token",
		ID:          "auth-token",
	}}
}

func (tc *TwilioConnector) CreateLogin(ctx context.Context, user *bridgev2.User, flowID string) (bridgev2.LoginProcess, error) {
	if flowID != "auth-token" {
		return nil, fmt.Errorf("unknown login flow ID")
	}
	return &TwilioLogin{User: user}, nil
}

type TwilioLogin struct {
	User         *bridgev2.User
	Client       *twilio.RestClient
	PhoneNumbers []twilioPhoneNumber
	AccountSID   string
	AuthToken    string
}

var _ bridgev2.LoginProcessUserInput = (*TwilioLogin)(nil)

func (tl *TwilioLogin) Start(ctx context.Context) (*bridgev2.LoginStep, error) {
	return &bridgev2.LoginStep{
		Type:         bridgev2.LoginStepTypeUserInput,
		StepID:       "fi.mau.twilio.enter_api_keys",
		Instructions: "",
		UserInputParams: &bridgev2.LoginUserInputParams{
			Fields: []bridgev2.LoginInputDataField{
				{
					Type:    bridgev2.LoginInputFieldTypeUsername,
					ID:      "account_sid",
					Name:    "Twilio account SID",
					Pattern: `^AC[0-9a-fA-F]{32}$`,
				},
				{
					Type:    bridgev2.LoginInputFieldTypePassword,
					ID:      "auth_token",
					Name:    "Twilio auth token",
					Pattern: "^[0-9a-f]{32}$",
				},
			},
		},
	}, nil
}

func (tl *TwilioLogin) SubmitUserInput(ctx context.Context, input map[string]string) (*bridgev2.LoginStep, error) {
	if tl.Client == nil {
		return tl.submitAPIKeys(ctx, input)
	} else {
		return tl.submitChosenPhoneNumber(ctx, input)
	}
}

type twilioPhoneNumber struct {
	SID          string
	Number       string
	PrettyNumber string
}

func (tl *TwilioLogin) submitAPIKeys(ctx context.Context, input map[string]string) (*bridgev2.LoginStep, error) {
	tl.AccountSID = input["account_sid"]
	tl.AuthToken = input["auth_token"]
	twilioClient := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username:   tl.AccountSID,
		Password:   tl.AuthToken,
		AccountSid: tl.AccountSID,
	})
	// Get the list of phone numbers. This doubles as a way to verify the credentials are valid.
	phoneNumbers, err := twilioClient.Api.ListIncomingPhoneNumber(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list phone numbers: %w", err)
	}
	var numbers []twilioPhoneNumber
	for _, number := range phoneNumbers {
		if number.Status == nil || number.PhoneNumber == nil || *number.Status != "in-use" {
			continue
		}
		numbers = append(numbers, twilioPhoneNumber{
			SID:          *number.Sid,
			Number:       *number.PhoneNumber,
			PrettyNumber: *number.FriendlyName,
		})
	}
	tl.Client = twilioClient
	tl.PhoneNumbers = numbers
	if len(numbers) == 0 {
		return nil, fmt.Errorf("no active phone numbers found")
	} else if len(numbers) == 1 {
		return tl.finishLogin(ctx, numbers[0])
	} else {
		phoneNumberList := make([]string, len(numbers))
		for i, number := range numbers {
			phoneNumberList[i] = fmt.Sprintf("* %s", number.Number)
		}
		return &bridgev2.LoginStep{
			Type:         bridgev2.LoginStepTypeUserInput,
			StepID:       "fi.mau.twilio.choose_number",
			Instructions: "Your Twilio account has multiple phone numbers. Please choose one:\n\n" + strings.Join(phoneNumberList, "\n"),
			UserInputParams: &bridgev2.LoginUserInputParams{
				Fields: []bridgev2.LoginInputDataField{{
					Type: bridgev2.LoginInputFieldTypePhoneNumber,
					ID:   "chosen_number",
					Name: "Phone number",
				}},
			},
		}, nil
	}
}

func (tl *TwilioLogin) submitChosenPhoneNumber(ctx context.Context, input map[string]string) (*bridgev2.LoginStep, error) {
	numberIdx := slices.IndexFunc(tl.PhoneNumbers, func(e twilioPhoneNumber) bool {
		return e.Number == input["chosen_number"]
	})
	if numberIdx == -1 {
		// We could also return a new LoginStep here if we wanted to allow the user to retry.
		// Errors are always fatal, so returning an error here will cancel the login process.
		return nil, fmt.Errorf("invalid phone number")
	}
	return tl.finishLogin(ctx, tl.PhoneNumbers[numberIdx])
}

func (tl *TwilioLogin) finishLogin(ctx context.Context, phoneNumber twilioPhoneNumber) (*bridgev2.LoginStep, error) {
	ul, err := tl.User.NewLogin(ctx, &database.UserLogin{
		ID: makeUserLoginID(tl.AccountSID, phoneNumber.SID),
		Metadata: database.UserLoginMetadata{
			StandardUserLoginMetadata: database.StandardUserLoginMetadata{
				RemoteName: phoneNumber.PrettyNumber,
			},
			Extra: map[string]any{
				"phone":       phoneNumber.Number,
				"phone_sid":   phoneNumber.SID,
				"auth_token":  tl.AuthToken,
				"account_sid": tl.AccountSID,
			},
		},
	}, &bridgev2.NewLoginParams{
		LoadUserLogin: func(ctx context.Context, login *bridgev2.UserLogin) error {
			login.Client = &TwilioClient{
				UserLogin:        login,
				Twilio:           tl.Client,
				RequestValidator: tclient.NewRequestValidator(tl.AuthToken),
			}
			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	tc := ul.Client.(*TwilioClient)
	// In addition to creating the UserLogin, we'll also want to set the webhook URL for the phone number.
	_, err = tc.Twilio.Api.UpdateIncomingPhoneNumber(phoneNumber.SID, &openapi.UpdateIncomingPhoneNumberParams{
		SmsMethod: ptr.Ptr(http.MethodPost),
		SmsUrl:    ptr.Ptr(tc.GetWebhookURL()),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to set webhook URL for phone number: %w", err)
	}
	// Finally, return the special complete step indicating the login was successful.
	// It doesn't have any params other than the UserLogin we just created.
	return &bridgev2.LoginStep{
		Type:         bridgev2.LoginStepTypeComplete,
		StepID:       "fi.mau.twilio.complete",
		Instructions: "Successfully logged in",
		CompleteParams: &bridgev2.LoginCompleteParams{
			UserLoginID: ul.ID,
			UserLogin:   ul,
		},
	}, nil
}

func (tl *TwilioLogin) Cancel() {}
