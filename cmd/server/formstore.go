package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	errFormNotFound = errors.New("formulário não encontrado")
	errFormExpired  = errors.New("formulário expirado")
	errFormUsed     = errors.New("formulário já utilizado")
)

const formCapabilityPrefix = "frm_"

type formInstance struct {
	ID           string
	SID          string
	To           string
	Chat         string
	Push         string
	Title        string
	Intro        string
	Submit       string
	Fields       []formField
	ExpiresAt    time.Time
	UsedAt       sql.NullTime
	SubmissionID sql.NullString
}

type formScanner interface {
	Scan(dest ...any) error
}

func newCapabilityToken() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("gerar token: %w", err)
	}
	token := formCapabilityPrefix + base64.RawURLEncoding.EncodeToString(raw)
	return token, hashCapabilityToken(token), nil
}

func newPublicID(prefix string) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("gerar identificador: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

func hashCapabilityToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func validCapabilityToken(token string) bool {
	if !strings.HasPrefix(token, formCapabilityPrefix) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, formCapabilityPrefix))
	return err == nil && len(raw) == 32
}

func (s *sessionStore) createForm(ctx context.Context, tokenHash string, form formInstance) error {
	fields, err := json.Marshal(form.Fields)
	if err != nil {
		return fmt.Errorf("serializar campos: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO form_instances
		(id, token_hash, session_id, to_jid, chat_jid, push_name, title, intro, submit_label, fields, expires_at)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7, NULLIF($8, ''), $9, $10, $11)`,
		form.ID, tokenHash, form.SID, form.To, form.Chat, form.Push, form.Title, form.Intro, form.Submit, fields, form.ExpiresAt)
	if err != nil {
		return fmt.Errorf("persistir formulário: %w", err)
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM form_instances
		WHERE expires_at < now() - interval '7 days'
		   OR used_at < now() - interval '7 days'`)
	return nil
}

func scanForm(scanner formScanner) (formInstance, error) {
	var form formInstance
	var fields []byte
	err := scanner.Scan(
		&form.ID, &form.SID, &form.To, &form.Chat, &form.Push, &form.Title,
		&form.Intro, &form.Submit, &fields, &form.ExpiresAt, &form.UsedAt, &form.SubmissionID,
	)
	if err != nil {
		return form, err
	}
	if err := json.Unmarshal(fields, &form.Fields); err != nil {
		return form, fmt.Errorf("ler campos do formulário: %w", err)
	}
	return form, nil
}

const selectFormInstance = `SELECT id, session_id, to_jid, chat_jid,
	COALESCE(push_name, ''), title, COALESCE(intro, ''), submit_label, fields,
	expires_at, used_at, submission_id
	FROM form_instances WHERE token_hash = $1`

func formAvailability(form formInstance, now time.Time) error {
	if form.UsedAt.Valid {
		return errFormUsed
	}
	if !now.Before(form.ExpiresAt) {
		return errFormExpired
	}
	return nil
}

func (s *sessionStore) getActiveForm(ctx context.Context, tokenHash string, now time.Time) (formInstance, error) {
	form, err := scanForm(s.db.QueryRowContext(ctx, selectFormInstance, tokenHash))
	if errors.Is(err, sql.ErrNoRows) {
		return form, errFormNotFound
	}
	if err != nil {
		return form, err
	}
	return form, formAvailability(form, now)
}

func (s *sessionStore) consumeForm(ctx context.Context, tokenHash string, now time.Time) (formInstance, string, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return formInstance{}, "", err
	}
	defer tx.Rollback()

	form, err := scanForm(tx.QueryRowContext(ctx, selectFormInstance+` FOR UPDATE`, tokenHash))
	if errors.Is(err, sql.ErrNoRows) {
		return form, "", errFormNotFound
	}
	if err != nil {
		return form, "", err
	}
	if err := formAvailability(form, now); err != nil {
		return form, "", err
	}

	submissionID, err := newPublicID("sub_")
	if err != nil {
		return form, "", err
	}
	result, err := tx.ExecContext(ctx, `UPDATE form_instances
		SET used_at = $2, submission_id = $3
		WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2`, tokenHash, now, submissionID)
	if err != nil {
		return form, "", err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return form, "", err
	}
	if affected != 1 {
		return form, "", errFormUsed
	}
	if err := tx.Commit(); err != nil {
		return form, "", err
	}
	return form, submissionID, nil
}
