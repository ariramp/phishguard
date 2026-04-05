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

	password, err := store.DecryptPassword(acc.PasswordEnc)
	if err != nil {
		cli.Close()
		return nil, fmt.Errorf("decrypt password: %w", err)
	}

	if err := cli.Login(acc.Username, password).Wait(); err != nil {
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

		if strings.TrimSpace(fm.MessageID) == "" {
			// Some mailboxes do not expose Message-ID reliably. Use a stable
			// fallback derived from the IMAP UID so we do not reinsert the same
			// message on the next polling cycle.
			fm.MessageID = fmt.Sprintf("<uid-%d@%s>", fm.UID, acc.EmailAddress)
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

func (c *Client) ApplyHighRiskAction(ctx context.Context, acc store.Account, uid uint32) error {
	action := strings.ToUpper(strings.TrimSpace(acc.ActionOnHigh))
	if action == "" || action == "NONE" {
		return nil
	}

	cli, err := c.dial(ctx, acc)
	if err != nil {
		return err
	}
	defer safeLogout(cli)

	mbox := acc.SourceMailbox
	if mbox == "" {
		mbox = "INBOX"
	}

	if _, err := cli.Select(mbox, nil).Wait(); err != nil {
		return fmt.Errorf("select mailbox %s: %w", mbox, err)
	}

	var uidSet imap.UIDSet
	uidSet.AddNum(imap.UID(uid))

	switch action {
	case "MOVE":
		target := strings.TrimSpace(acc.TargetMailbox)
		if target == "" {
			target = "Phishing"
		}
		if _, err := cli.Move(uidSet, target).Wait(); err != nil {
			if errCreate := ensureMailbox(cli, target); errCreate != nil {
				return fmt.Errorf("move message to %s: %w", target, err)
			}
			if _, err := cli.Move(uidSet, target).Wait(); err != nil {
				return fmt.Errorf("move message to %s after create: %w", target, err)
			}
		}
		return nil
	case "COPY":
		target := strings.TrimSpace(acc.TargetMailbox)
		if target == "" {
			target = "Phishing"
		}
		if _, err := cli.Copy(uidSet, target).Wait(); err != nil {
			if errCreate := ensureMailbox(cli, target); errCreate != nil {
				return fmt.Errorf("copy message to %s: %w", target, err)
			}
			if _, err := cli.Copy(uidSet, target).Wait(); err != nil {
				return fmt.Errorf("copy message to %s after create: %w", target, err)
			}
		}
		return nil
	case "TAG":
		storeFlags := &imap.StoreFlags{
			Op:     imap.StoreFlagsAdd,
			Silent: true,
			Flags:  []imap.Flag{imap.FlagFlagged},
		}
		if err := cli.Store(uidSet, storeFlags, nil).Close(); err != nil {
			return fmt.Errorf("flag message: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported action_on_high: %s", action)
	}
}

func ensureMailbox(cli *imapclient.Client, mailbox string) error {
	if strings.TrimSpace(mailbox) == "" {
		return nil
	}
	if err := cli.Create(mailbox, nil).Wait(); err != nil && !mailboxAlreadyExists(err) {
		return err
	}
	return nil
}

func mailboxAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already exists") || strings.Contains(msg, "mailbox exists")
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
