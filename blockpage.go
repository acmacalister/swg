package swg

import (
	"html/template"
	"io"
	"net/http"
	"strings"
)

// BlockPage represents a customizable block page.
type BlockPage struct {
	template *template.Template
}

// BlockPageData contains the data passed to the block page template.
type BlockPageData struct {
	URL       string
	Host      string
	Path      string
	Reason    string
	Timestamp string
}

// DefaultBlockPageHTML is the default block page template.
const DefaultBlockPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Blocked - SWG</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #e0e0e0;
        }
        .container {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px 50px;
            max-width: 600px;
            width: 90%;
            border: 1px solid rgba(255, 255, 255, 0.1);
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.3);
        }
        .icon {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #e74c3c, #c0392b);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 25px;
        }
        .icon svg {
            width: 40px;
            height: 40px;
            fill: white;
        }
        h1 {
            font-size: 28px;
            font-weight: 600;
            text-align: center;
            margin-bottom: 15px;
            color: #fff;
        }
        .subtitle {
            text-align: center;
            color: #a0a0a0;
            margin-bottom: 30px;
            font-size: 16px;
        }
        .details {
            background: rgba(0, 0, 0, 0.2);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 25px;
        }
        .detail-row {
            display: flex;
            margin-bottom: 12px;
        }
        .detail-row:last-child {
            margin-bottom: 0;
        }
        .detail-label {
            color: #888;
            min-width: 80px;
            font-size: 14px;
        }
        .detail-value {
            color: #fff;
            word-break: break-all;
            font-size: 14px;
        }
        .reason-badge {
            display: inline-block;
            background: rgba(231, 76, 60, 0.2);
            color: #e74c3c;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 500;
        }
        .footer {
            text-align: center;
            color: #666;
            font-size: 13px;
        }
        .footer a {
            color: #3498db;
            text-decoration: none;
        }
        .footer a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">
            <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
            </svg>
        </div>
        <h1>Access Blocked</h1>
        <p class="subtitle">This website has been blocked by your network administrator.</p>
        
        <div class="details">
            <div class="detail-row">
                <span class="detail-label">URL</span>
                <span class="detail-value">{{.URL}}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Host</span>
                <span class="detail-value">{{.Host}}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Reason</span>
                <span class="detail-value"><span class="reason-badge">{{.Reason}}</span></span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Time</span>
                <span class="detail-value">{{.Timestamp}}</span>
            </div>
        </div>
        
        <p class="footer">
            Protected by <strong>SWG</strong> &mdash; Secure Web Gateway
        </p>
    </div>
</body>
</html>`

// NewBlockPage creates a new BlockPage with the default template.
func NewBlockPage() *BlockPage {
	tmpl := template.Must(template.New("block").Parse(DefaultBlockPageHTML))
	return &BlockPage{template: tmpl}
}

// NewBlockPageFromTemplate creates a BlockPage from a custom template string.
func NewBlockPageFromTemplate(templateStr string) (*BlockPage, error) {
	tmpl, err := template.New("block").Parse(templateStr)
	if err != nil {
		return nil, err
	}
	return &BlockPage{template: tmpl}, nil
}

// NewBlockPageFromFile creates a BlockPage from a template file.
func NewBlockPageFromFile(path string) (*BlockPage, error) {
	tmpl, err := template.ParseFiles(path)
	if err != nil {
		return nil, err
	}
	return &BlockPage{template: tmpl}, nil
}

// Render writes the block page to the given writer.
func (bp *BlockPage) Render(w io.Writer, data BlockPageData) error {
	return bp.template.Execute(w, data)
}

// RenderString returns the block page as a string.
func (bp *BlockPage) RenderString(data BlockPageData) (string, error) {
	var sb strings.Builder
	if err := bp.template.Execute(&sb, data); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// ServeHTTP implements http.Handler for serving the block page directly.
func (bp *BlockPage) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data := BlockPageData{
		URL:       r.URL.Query().Get("url"),
		Host:      r.URL.Query().Get("host"),
		Path:      r.URL.Query().Get("path"),
		Reason:    r.URL.Query().Get("reason"),
		Timestamp: r.URL.Query().Get("time"),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_ = bp.template.Execute(w, data)
}
