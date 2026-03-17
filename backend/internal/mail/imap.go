package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
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

func (c *Client) dial(ctx context.Context, acc store.Account) (*imapclient.Client, error) {
	dialer := net.Dialer{
		Timeout: 10 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", acc.IMAPHost, acc.IMAPPort)

	var conn net.Conn
	var err error

	if acc.IMAPTLS {
		conn, err = tls.DialWithDialer(&dialer, "tcp", addr, &tls.Config{
			ServerName: acc.IMAPHost,
		})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	cli := imapclient.New(conn, nil)

	if err := cli.Login(acc.Username, string(acc.PasswordEnc)).Wait(); err != nil {
		cli.Close()
		return nil, fmt.Errorf("login: %w", err)
	}

	return cli, nil
}

func safeLogout(cli *imapclient.Client) {
	if cli == nil {
		return
	}
	_ = cli.Logout().Wait()
	_ = cli.Close()
}

func (c *Client) GetCurrentMaxUID(ctx context.Context, acc store.Account) (uint32, error) {
	cli, err := c.dial(ctx, acc)
	if err != nil {
		return 0, err
	}
	defer safeLogout(cli)

	mbox := acc.SourceMailbox
	if mbox == "" {
		mbox = "INBOX"
	}

	selected, err := cli.Select(mbox, nil).Wait()
	if err != nil {
		return 0, fmt.Errorf("select mailbox %s: %w", mbox, err)
	}

	if selected == nil || selected.NumMessages == 0 {
		return 0, nil
	}

	if selected.UIDNext > 0 {
		return uint32(selected.UIDNext - 1), nil
	}

	return 0, nil
}

func (c *Client) FetchNewMessages(ctx context.Context, acc store.Account) ([]FetchedMessage, uint32, error) {
	cli, err := c.dial(ctx, acc)
	if err != nil {
		return nil, 0, err
	}
	defer safeLogout(cli)

	mbox := acc.SourceMailbox
	if mbox == "" {
		mbox = "INBOX"
	}

	selected, err := cli.Select(mbox, nil).Wait()
	if err != nil {
		return nil, 0, fmt.Errorf("select mailbox %s: %w", mbox, err)
	}

	if selected == nil || selected.NumMessages == 0 {
		return nil, 0, nil
	}

	startUID := uint32(acc.LastUID + 1)
	if startUID == 0 {
		startUID = 1
	}

	var endUID uint32
	if selected.UIDNext > 0 {
		endUID = uint32(selected.UIDNext - 1)
	}

	if endUID == 0 || startUID > endUID {
		return nil, 0, nil
	}

	fetchOptions := &imap.FetchOptions{
		UID:          true,
		Envelope:     true,
		InternalDate: true,
		BodySection: []*imap.FetchItemBodySection{
			{Specifier: imap.PartSpecifierNone},
		},
	}

	var out []FetchedMessage
	var maxUID uint32

	for uid := startUID; uid <= endUID; uid++ {
		var uidSet imap.UIDSet
		uidSet.AddNum(imap.UID(uid))

		messages, err := cli.Fetch(uidSet, fetchOptions).Collect()
		if err != nil {
			// не валим весь poll из-за одного письма
			continue
		}
		if len(messages) == 0 {
			continue
		}

		msg := messages[0]

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
