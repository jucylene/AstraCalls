package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"
)

// Formulários (form nativo-like) para número NÃO-OFICIAL.
//
// O WhatsApp Flows (form nativo de verdade) exige WABA/conta oficial — o flow_id
// é validado contra o Meta e NÃO abre num número não-oficial. A alternativa que
// FUNCIONA é um botão que abre uma WEBVIEW em tela cheia DENTRO do WhatsApp
// (cta_url + webview_presentation=full): o cliente preenche sem sair do app.
//
// Fluxo:
//   POST /api/sessions/{sid}/messages/form  -> persiste o formulário e manda uma
//     mensagem interativa com botão webview apontando para /forms/{token}. A rota
//     é pública porque o celular do cliente não tem a chave da API.
//   GET  /forms/{token}          -> renderiza o HTML do formulário.
//   POST /forms/{token}/submit   -> recebe o preenchimento: injeta como mensagem
//     recebida (Chatwoot + webhook "message"), dispara o evento "form_response" e
//     manda uma confirmação no WhatsApp.

// formField descreve um campo do formulário.
type formField struct {
	Name        string   `json:"name"`
	Label       string   `json:"label"`
	Type        string   `json:"type"`    // text|email|tel|number|textarea|select|date
	Options     []string `json:"options"` // para select
	Placeholder string   `json:"placeholder"`
	Required    bool     `json:"required"`
}

const (
	defaultFormTTL        = 24 * time.Hour
	minFormTTL            = 5 * time.Minute
	maxFormTTL            = 7 * 24 * time.Hour
	maxFormFields         = 30
	maxFormRequestBytes   = 64 << 10
	maxFormValueLength    = 512
	maxFormTextAreaLength = 4096
)

var (
	formFieldNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)
	formPhonePattern     = regexp.MustCompile(`^[0-9+(). -]{7,30}$`)
)

func normalizeFormTTL(seconds int) (time.Duration, error) {
	if seconds == 0 {
		return defaultFormTTL, nil
	}
	ttl := time.Duration(seconds) * time.Second
	if ttl < minFormTTL || ttl > maxFormTTL {
		return 0, fmt.Errorf("expiresInSeconds deve estar entre %d e %d", int(minFormTTL.Seconds()), int(maxFormTTL.Seconds()))
	}
	return ttl, nil
}

func normalizeFormFields(fields []formField) ([]formField, error) {
	if len(fields) == 0 || len(fields) > maxFormFields {
		return nil, fmt.Errorf("fields deve conter entre 1 e %d campos", maxFormFields)
	}
	seen := make(map[string]struct{}, len(fields))
	out := make([]formField, len(fields))
	for i, field := range fields {
		field.Name = strings.TrimSpace(field.Name)
		field.Label = strings.TrimSpace(field.Label)
		field.Placeholder = strings.TrimSpace(field.Placeholder)
		field.Type = strings.TrimSpace(field.Type)
		if field.Type == "" {
			field.Type = "text"
		}
		if !formFieldNamePattern.MatchString(field.Name) {
			return nil, fmt.Errorf("nome de campo inválido: %q", field.Name)
		}
		if _, exists := seen[field.Name]; exists {
			return nil, fmt.Errorf("campo duplicado: %q", field.Name)
		}
		seen[field.Name] = struct{}{}
		if len(field.Label) > 120 || len(field.Placeholder) > 200 {
			return nil, fmt.Errorf("texto do campo %q excede o limite", field.Name)
		}
		switch field.Type {
		case "text", "email", "tel", "number", "date", "textarea":
			field.Options = nil
		case "select":
			if len(field.Options) == 0 || len(field.Options) > 50 {
				return nil, fmt.Errorf("campo select %q deve ter entre 1 e 50 opções", field.Name)
			}
			for optionIndex, option := range field.Options {
				option = strings.TrimSpace(option)
				if option == "" || len(option) > 120 {
					return nil, fmt.Errorf("opção inválida no campo %q", field.Name)
				}
				field.Options[optionIndex] = option
			}
		default:
			return nil, fmt.Errorf("tipo inválido no campo %q", field.Name)
		}
		out[i] = field
	}
	return out, nil
}

func validateFormAnswers(fields []formField, values url.Values) (map[string]string, error) {
	answers := make(map[string]string, len(fields))
	for _, field := range fields {
		value := strings.TrimSpace(values.Get(field.Name))
		label := field.Label
		if label == "" {
			label = field.Name
		}
		if field.Required && value == "" {
			return nil, fmt.Errorf("campo obrigatório: %s", label)
		}
		limit := maxFormValueLength
		if field.Type == "textarea" {
			limit = maxFormTextAreaLength
		}
		if len(value) > limit {
			return nil, fmt.Errorf("campo %s excede o limite", label)
		}
		if value != "" {
			switch field.Type {
			case "email":
				address, err := mail.ParseAddress(value)
				if err != nil || address.Address != value {
					return nil, fmt.Errorf("e-mail inválido no campo %s", label)
				}
			case "tel":
				if !formPhonePattern.MatchString(value) {
					return nil, fmt.Errorf("telefone inválido no campo %s", label)
				}
			case "number":
				if _, err := strconv.ParseFloat(value, 64); err != nil {
					return nil, fmt.Errorf("número inválido no campo %s", label)
				}
			case "date":
				if _, err := time.Parse("2006-01-02", value); err != nil {
					return nil, fmt.Errorf("data inválida no campo %s", label)
				}
			case "select":
				valid := false
				for _, option := range field.Options {
					if value == option {
						valid = true
						break
					}
				}
				if !valid {
					return nil, fmt.Errorf("opção inválida no campo %s", label)
				}
			}
		}
		answers[field.Name] = value
	}
	return answers, nil
}

func setFormSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func writeFormAccessError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errFormExpired):
		http.Error(w, "link expirado", http.StatusGone)
	case errors.Is(err, errFormUsed):
		http.Error(w, "formulário já respondido", http.StatusConflict)
	case errors.Is(err, errFormNotFound):
		http.Error(w, "link inválido", http.StatusNotFound)
	default:
		http.Error(w, "erro ao abrir formulário", http.StatusInternalServerError)
	}
}

// publicBaseURL deriva a URL pública: env WACALLS_PUBLIC_BASE_URL ou o Host da
// requisição (atrás do Traefik, com https).
func publicBaseURL(r *http.Request) string {
	if b := strings.TrimRight(os.Getenv("WACALLS_PUBLIC_BASE_URL"), "/"); b != "" {
		return b
	}
	scheme := "https"
	if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		scheme = p
	} else if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

// POST /api/sessions/{sid}/messages/form
// {to, title?, body?, footer?, submitText?, buttonText?,
//
//	fields:[{name,label,type,options[],placeholder,required}]}
func (s *server) handleSendForm(w http.ResponseWriter, r *http.Request) {
	sess := s.pairedSession(w, r.PathValue("sid"))
	if sess == nil {
		return
	}
	var b struct {
		To               string      `json:"to"`
		Title            string      `json:"title"`
		Body             string      `json:"body"`
		Footer           string      `json:"footer"`
		SubmitText       string      `json:"submitText"`
		ButtonText       string      `json:"buttonText"`
		ExpiresInSeconds int         `json:"expiresInSeconds"`
		Fields           []formField `json:"fields"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || strings.TrimSpace(b.To) == "" || len(b.Fields) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "to e fields obrigatórios"})
		return
	}
	fields, err := normalizeFormFields(b.Fields)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ttl, err := normalizeFormTTL(b.ExpiresInSeconds)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	jid, err := resolveRecipient(b.To)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if b.Title == "" {
		b.Title = "Formulário"
	}
	if b.SubmitText == "" {
		b.SubmitText = "Enviar"
	}
	if b.ButtonText == "" {
		b.ButtonText = "Abrir formulário"
	}
	token, tokenHash, err := newCapabilityToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "não foi possível criar o formulário"})
		return
	}
	formID, err := newPublicID("form_")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "não foi possível criar o formulário"})
		return
	}
	form := formInstance{
		ID: formID, SID: sess.id, To: jid.String(), Chat: jid.String(),
		Title: b.Title, Intro: b.Body, Submit: b.SubmitText,
		Fields: fields, ExpiresAt: time.Now().UTC().Add(ttl),
	}
	if err := s.sessions.store.createForm(r.Context(), tokenHash, form); err != nil {
		s.log.Error("form create failed", "err", err, "session", sess.id)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "não foi possível criar o formulário"})
		return
	}
	formURL := publicBaseURL(r) + "/forms/" + token

	// Botão webview (cta_url + webview_presentation=full) — abre a webview no app.
	name, params := nativeFlowButton("webview", b.ButtonText, formURL, "", "", "", 0)
	msg := &waE2E.Message{
		InteractiveMessage: &waE2E.InteractiveMessage{
			Body:   &waE2E.InteractiveMessage_Body{Text: proto.String(strings.TrimSpace(b.Title + "\n\n" + b.Body))},
			Footer: &waE2E.InteractiveMessage_Footer{Text: proto.String(b.Footer)},
			InteractiveMessage: &waE2E.InteractiveMessage_NativeFlowMessage_{
				NativeFlowMessage: &waE2E.InteractiveMessage_NativeFlowMessage{
					Buttons: []*waE2E.InteractiveMessage_NativeFlowMessage_NativeFlowButton{{
						Name: proto.String(name), ButtonParamsJSON: proto.String(params),
					}},
					MessageParamsJSON: proto.String(""), MessageVersion: proto.Int32(1),
				},
			},
		},
		MessageContextInfo: &waE2E.MessageContextInfo{MessageSecret: newMessageSecret()},
	}
	s.sendNativeFlowWithExtras(sess, w, r, jid, msg, map[string]any{
		"form_id":    form.ID,
		"expires_at": form.ExpiresAt.Format(time.RFC3339),
	})
}

// GET /forms/{token} — renderiza o HTML (rota pública).
func (s *server) handleFormPage(w http.ResponseWriter, r *http.Request) {
	setFormSecurityHeaders(w)
	token := r.PathValue("token")
	if !validCapabilityToken(token) {
		writeFormAccessError(w, errFormNotFound)
		return
	}
	form, err := s.sessions.store.getActiveForm(r.Context(), hashCapabilityToken(token), time.Now().UTC())
	if err != nil {
		writeFormAccessError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, renderFormHTML(form, "/forms/"+token+"/submit"))
}

// POST /forms/{token}/submit — recebe o preenchimento (rota pública).
func (s *server) handleFormSubmit(w http.ResponseWriter, r *http.Request) {
	setFormSecurityHeaders(w)
	token := r.PathValue("token")
	if !validCapabilityToken(token) {
		writeFormAccessError(w, errFormNotFound)
		return
	}
	tokenHash := hashCapabilityToken(token)
	form, err := s.sessions.store.getActiveForm(r.Context(), tokenHash, time.Now().UTC())
	if err != nil {
		writeFormAccessError(w, err)
		return
	}
	sess, ok := s.sessions.Get(form.SID)
	if !ok {
		http.Error(w, "sessão indisponível", http.StatusGone)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormRequestBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "erro ao ler formulário", http.StatusBadRequest)
		return
	}
	answers, err := validateFormAnswers(form.Fields, r.PostForm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	chat, err := resolveRecipient(form.Chat)
	if err != nil {
		http.Error(w, "destinatário inválido", http.StatusInternalServerError)
		return
	}
	submittedAt := time.Now().UTC()
	form, submissionID, err := s.sessions.store.consumeForm(r.Context(), tokenHash, submittedAt)
	if err != nil {
		writeFormAccessError(w, err)
		return
	}

	var sb strings.Builder
	sb.WriteString("📋 *" + form.Title + "*\n")
	for _, f := range form.Fields {
		v := answers[f.Name]
		label := f.Label
		if label == "" {
			label = f.Name
		}
		sb.WriteString("\n*" + label + ":* " + v)
	}
	summary := sb.String()

	synthetic := &events.Message{
		Info: types.MessageInfo{
			MessageSource: types.MessageSource{Chat: chat, Sender: chat},
			ID:            sess.client.GenerateMessageID(),
			Timestamp:     submittedAt,
			PushName:      form.Push,
		},
		Message: &waE2E.Message{Conversation: proto.String(summary)},
	}
	sess.storeMessageEvent(synthetic)
	sess.dispatchWebhook("message", sess.messagePayload(synthetic))
	go sess.chatwootPushIncoming(synthetic)
	sess.dispatchWebhook("form_response", map[string]any{
		"form_id":       form.ID,
		"submission_id": submissionID,
		"submitted_at":  submittedAt.Format(time.RFC3339Nano),
		"title":         form.Title,
		"from":          form.To,
		"answers":       answers,
	})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, formThanksHTML(form.Title))
}

func renderFormHTML(t formInstance, action string) string {
	var fields strings.Builder
	for _, f := range t.Fields {
		req := ""
		if f.Required {
			req = " required"
		}
		lbl := html.EscapeString(f.Label)
		if f.Required {
			lbl += " <span class=req>*</span>"
		}
		ph := html.EscapeString(f.Placeholder)
		name := html.EscapeString(f.Name)
		fields.WriteString(`<label>` + lbl)
		switch f.Type {
		case "textarea":
			fields.WriteString(`<textarea name="` + name + `" rows="4" placeholder="` + ph + `"` + req + `></textarea>`)
		case "select":
			fields.WriteString(`<select name="` + name + `"` + req + `><option value="" disabled selected>` + ph + `</option>`)
			for _, o := range f.Options {
				oe := html.EscapeString(o)
				fields.WriteString(`<option value="` + oe + `">` + oe + `</option>`)
			}
			fields.WriteString(`</select>`)
		default:
			typ := f.Type
			switch typ {
			case "email", "tel", "number", "date":
			default:
				typ = "text"
			}
			fields.WriteString(`<input type="` + typ + `" name="` + name + `" placeholder="` + ph + `"` + req + `>`)
		}
		fields.WriteString(`</label>`)
	}
	return `<!doctype html><html lang=pt-BR><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>` + html.EscapeString(t.Title) + `</title><style>
:root{--navy:#233E4F;--blue:#89CFF3}
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f4f6f8;color:#1c2a33}
.wrap{max-width:520px;margin:0 auto;padding:20px 16px 48px}
h1{color:var(--navy);font-size:22px;margin:8px 0 4px}
p.intro{color:#5a6b76;margin:0 0 20px}
form{display:flex;flex-direction:column;gap:16px}
label{display:flex;flex-direction:column;gap:6px;font-weight:600;font-size:14px;color:var(--navy)}
input,select,textarea{font:inherit;font-weight:400;padding:12px 14px;border:1px solid #cdd8df;border-radius:12px;background:#fff;color:#1c2a33}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 3px rgba(137,207,243,.35)}
.req{color:#e0484d}
button{margin-top:8px;padding:14px;border:0;border-radius:12px;background:var(--navy);color:#fff;font-size:16px;font-weight:700;cursor:pointer}
button:active{transform:scale(.99)}
</style></head><body><div class=wrap>
<h1>` + html.EscapeString(t.Title) + `</h1>` +
		intoSup(t.Intro) + `
<form method=post action="` + html.EscapeString(action) + `">` + fields.String() + `
<button type=submit>` + html.EscapeString(t.Submit) + `</button>
</form></div></body></html>`
}

func intoSup(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return `<p class=intro>` + html.EscapeString(s) + `</p>`
}

func formThanksHTML(title string) string {
	return `<!doctype html><html lang=pt-BR><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Enviado</title><style>
body{margin:0;font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f4f6f8;color:#233E4F;
display:flex;min-height:100vh;align-items:center;justify-content:center;text-align:center;padding:24px}
.card{background:#fff;border-radius:20px;padding:36px 28px;box-shadow:0 10px 40px rgba(35,62,79,.12);max-width:420px}
.ico{font-size:56px}h1{font-size:22px;margin:12px 0 6px}p{color:#5a6b76;margin:0}
</style></head><body><div class=card><div class=ico>✅</div>
<h1>Recebemos suas respostas!</h1><p>Obrigado por preencher o formulário. Já pode fechar esta janela.</p>
</div></body></html>`
}
