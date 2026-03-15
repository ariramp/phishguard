package mail

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"phishguard/backend/internal/store"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	gomail "github.com/emersion/go-message/mail"
)

type FetchedMessage struct {
	UID        uint32
	MessageID  string
	Subject    string
	From       string
	ReceivedAt *time.Time
	TextBody   string
	HTMLBody   string
}

type Client struct{}

func NewClient() *Client {
	return &Client{}
}

func (c *Client) FetchNewMessages(ctx context.Context, acc store.Account) ([]FetchedMessage, uint32, error) {
	_ = ctx

	addr := fmt.Sprintf("%s:%d", acc.IMAPHost, acc.IMAPPort)

	var cli *imapclient.Client
	var err error

	if acc.IMAPTLS {
		cli, err = imapclient.DialTLS(addr, nil)
	} else {
		cli, err = imapclient.DialInsecure(addr, nil)
	}
	if err != nil {
		return nil, 0, err
	}
	defer cli.Close()

	if err := cli.Login(acc.Username, string(acc.PasswordEnc)).Wait(); err != nil {
		return nil, 0, err
	}

	mbox := acc.SourceMailbox
	if mbox == "" {
		mbox = "INBOX"
	}

	selected, err := cli.Select(mbox, nil).Wait()
	if err != nil {
		return nil, 0, err
	}

	if selected == nil || selected.NumMessages == 0 {
		_ = cli.Logout().Wait()
		return nil, 0, nil
	}

	startUID := imap.UID(acc.LastUID + 1)
	if startUID == 0 {
		startUID = 1
	}

	// Берём диапазон UID: от last_uid+1 до максимума
	var uidSet imap.UIDSet
	uidSet.AddRange(startUID, imap.UID(^uint32(0)))

	fetchOptions := &imap.FetchOptions{
		UID:          true,
		Envelope:     true,
		InternalDate: true,
		BodySection: []*imap.FetchItemBodySection{
			{Specifier: imap.PartSpecifierNone},
		},
	}

	messages, err := cli.Fetch(uidSet, fetchOptions).Collect()
	if err != nil {
		return nil, 0, err
	}

	var out []FetchedMessage
	var maxUID uint32

	for _, msg := range messages {
		fm := FetchedMessage{
			UID: uint32(msg.UID),
		}

		if fm.UID > maxUID {
			maxUID = fm.UID
		}

		if msg.Envelope != nil {
			fm.Subject = msg.Envelope.Subject
			fm.MessageID = msg.Envelope.MessageID

			if len(msg.Envelope.From) > 0 {
				addr := msg.Envelope.From[0]
				fm.From = strings.TrimSpace(addr.Mailbox + "@" + addr.Host)
			}
		}

		if !msg.InternalDate.IsZero() {
			t := msg.InternalDate
			fm.ReceivedAt = &t
		}

		for _, sec := range msg.BodySection {
			textBody, htmlBody := extractBodies(sec.Bytes)
			if textBody != "" {
				fm.TextBody = textBody
			}
			if htmlBody != "" {
				fm.HTMLBody = htmlBody
			}
		}

		out = append(out, fm)
	}

	if err := cli.Logout().Wait(); err != nil {
		return nil, 0, err
	}

	return out, maxUID, nil
}

func extractBodies(raw []byte) (string, string) {
	mr, err := gomail.CreateReader(bytes.NewReader(raw))
	if err != nil {
		return string(raw), ""
	}

	var textBody string
	var htmlBody string

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		switch h := part.Header.(type) {
		case *gomail.InlineHeader:
			ct, _, _ := h.ContentType()
			b, _ := io.ReadAll(part.Body)

			switch strings.ToLower(ct) {
			case "text/plain":
				textBody = string(b)
			case "text/html":
				htmlBody = string(b)
			}
		}
	}

	if textBody == "" && htmlBody == "" {
		return string(raw), ""
	}

	return textBody, htmlBody
}
