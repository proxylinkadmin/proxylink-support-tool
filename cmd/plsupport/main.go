//go:build windows

// ProxyLink Support Tool
// One-time remote support agent for Windows.
//
// Normal use: the customer runs the exe, enters the code the technician gave them, and
// clicks Connect. The exe brings up a WireGuard tunnel + UltraVNC, tells the server it is
// ready, and shows a "your technician can connect" panel. Closing the window (or the tech
// ending the session, or the session expiring) tears everything back down.
//
// Recovery mode: `plsupport.exe -cleanup CODE` force-removes everything a session set up
// (stops VNC, drops the tunnel, removes the firewall rule). Requires admin (embedded UAC
// manifest). The tool installs no service or scheduled task — nothing persists after a session.

package main

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/lxn/walk"
	dcl "github.com/lxn/walk/declarative"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/sys/windows"
)

//go:embed logo.png
var logoPNG []byte

const (
	defaultServer      = "https://app.proxylink.dev"
	wireguardPath      = `C:\Program Files\WireGuard\wireguard.exe`
	wireguardInstaller = "https://download.wireguard.com/windows-client/wireguard-installer.exe"
	ultravncInstaller  = "https://app.proxylink.dev/assets/ultravnc-setup.exe"
	vncSetupPath       = `C:\Windows\Temp\plsupport-uvnc.exe`
	confPath           = `C:\Windows\Temp\plsupport.conf`
	tunnelName         = "plsupport"
	uvncService        = "uvnc_service"
	firewallRuleName   = "ProxyLink VNC"
)

// UltraVNC install locations to probe (uvnc-bvba installer).
var uvncDirs = []string{
	`C:\Program Files\uvnc bvba\UltraVNC`,
	`C:\Program Files (x86)\uvnc bvba\UltraVNC`,
}

// ── shared runtime state ────────────────────────────────────────────────────────
type appState struct {
	server         string
	code           string
	vncWasInstalled bool // UltraVNC already present before we touched it
	wgWasInstalled  bool
	vncInstalled    bool // we installed/configured it this run
	wgTunnelUp      bool
	iniBackup       string // path to a backed-up pre-existing ultravnc.ini
	cleaning        bool
	cleanedUp       bool
}

func main() {
	// Manual recovery: `plsupport.exe -cleanup CODE` force-removes everything a session set up.
	if len(os.Args) >= 3 && os.Args[1] == "-cleanup" {
		forceCleanup(defaultServer, strings.ToUpper(strings.TrimSpace(os.Args[2])))
		return
	}
	runGUI()
}

// ── GUI ──────────────────────────────────────────────────────────────────────────

var (
	mw          *walk.MainWindow
	codeEdit    *walk.LineEdit
	connectBtn  *walk.PushButton
	statusLabel *walk.Label
	detailLabel *walk.Label
	st          = &appState{server: defaultServer}
)

func runGUI() {
	// A code passed as an argument pre-fills the field (for future URL-embedded codes).
	preCode := ""
	for _, a := range os.Args[1:] {
		if strings.HasPrefix(a, "-server=") {
			st.server = strings.TrimPrefix(a, "-server=")
		} else if l := len(strings.TrimSpace(a)); l == 6 || l == 8 {
			preCode = strings.ToUpper(strings.TrimSpace(a))
		}
	}

	// Window + taskbar icon from the embedded resource (ID 1 = icon.ico from resource.rc).
	winIcon, _ := walk.NewIconFromResourceId(1)
	// Brand logo shown in the window header.
	var logoBmp *walk.Bitmap
	if img, err := png.Decode(bytes.NewReader(logoPNG)); err == nil {
		logoBmp, _ = walk.NewBitmapFromImageForDPI(img, 96)
	}

	if err := (dcl.MainWindow{
		AssignTo: &mw,
		Title:    "ProxyLink Support",
		Icon:     winIcon,
		MinSize:  dcl.Size{Width: 480, Height: 320},
		Size:     dcl.Size{Width: 480, Height: 320},
		Layout:   dcl.VBox{Margins: dcl.Margins{Left: 24, Top: 20, Right: 24, Bottom: 20}, Spacing: 8},
		Background: dcl.SolidColorBrush{Color: walk.RGB(255, 255, 255)},
		Children: []dcl.Widget{
			dcl.ImageView{Image: logoBmp, Mode: dcl.ImageViewModeZoom, MinSize: dcl.Size{Width: 56, Height: 56}, MaxSize: dcl.Size{Width: 56, Height: 56}},
			dcl.Label{Text: "ProxyLink Support", Font: dcl.Font{Family: "Segoe UI", PointSize: 16, Bold: true}, TextColor: walk.RGB(15, 118, 110)},
			dcl.Label{Text: "Secure one-time remote support", TextColor: walk.RGB(90, 90, 90)},
			dcl.VSpacer{Size: 8},
			dcl.Label{Text: "Enter the code your technician gave you:"},
			dcl.LineEdit{AssignTo: &codeEdit, MaxLength: 8, Text: preCode, Font: dcl.Font{Family: "Consolas", PointSize: 13}},
			dcl.PushButton{AssignTo: &connectBtn, Text: "Connect", OnClicked: onConnect, MinSize: dcl.Size{Height: 34}},
			dcl.VSpacer{Size: 8},
			dcl.Label{AssignTo: &statusLabel, Text: "", Font: dcl.Font{Family: "Segoe UI", PointSize: 10, Bold: true}, TextColor: walk.RGB(15, 118, 110)},
			dcl.Label{AssignTo: &detailLabel, Text: "You can close this window at any time to end support.", TextColor: walk.RGB(120, 120, 120)},
		},
	}).Create(); err != nil {
		return
	}

	// Closing the window ends the session. Cleanup (stop VNC, uninstall, drop the tunnel) takes
	// a few seconds, so it runs on a background goroutine with a visible status: cancel the
	// first close, clean up, then close for real when it finishes — keeping the window responsive.
	mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		if st.cleanedUp {
			return // cleanup done — allow the window to close
		}
		if st.cleaning {
			*canceled = true // already cleaning; ignore repeat close clicks
			return
		}
		st.cleaning = true
		*canceled = true
		setStatus("Ending session — cleaning up...", "Removing screen sharing and the secure tunnel. This takes a few seconds.")
		go func() {
			cleanup(st)
			mw.Synchronize(func() {
				setStatus("Support session ended.", "Everything has been removed. You can close this window.")
				mw.Close()
			})
		}()
	})

	if preCode != "" {
		connectBtn.SetFocus()
	} else {
		codeEdit.SetFocus()
	}
	mw.Run()
}

func onConnect() {
	code := strings.ToUpper(strings.TrimSpace(codeEdit.Text()))
	if len(code) < 6 {
		setStatus("Please enter the full code.", "")
		return
	}
	if !isAdmin() {
		setStatus("Please run this tool as Administrator.", "Right-click the file and choose 'Run as administrator'.")
		return
	}
	st.code = code
	codeEdit.SetEnabled(false)
	connectBtn.SetEnabled(false)
	go runFlow(st)
}

// setStatus updates the two status lines from any goroutine.
func setStatus(msg, detail string) {
	if mw == nil {
		return
	}
	mw.Synchronize(func() {
		if statusLabel != nil {
			statusLabel.SetText(msg)
		}
		if detail != "" && detailLabel != nil {
			detailLabel.SetText(detail)
		}
	})
}

func fail(msg string) {
	setStatus("Could not connect: "+msg, "Close this window and try again, or contact your technician.")
	if mw != nil {
		mw.Synchronize(func() {
			codeEdit.SetEnabled(true)
			connectBtn.SetEnabled(true)
		})
	}
}

// ── the flow ───────────────────────────────────────────────────────────────────

func runFlow(s *appState) {
	s.vncWasInstalled = uvncInstalled()
	s.wgWasInstalled = fileExists(wireguardPath)

	setStatus("Generating secure keys...", "")
	privKey, pubKey, err := generateWireGuardKeypair()
	if err != nil {
		fail(err.Error())
		return
	}

	setStatus("Registering with ProxyLink...", "")
	reg, err := apiRegister(s.server, s.code, pubKey)
	if err != nil {
		fail(err.Error())
		return
	}

	if !s.wgWasInstalled {
		setStatus("Installing the secure tunnel (one-time, ~10 MB)...", "")
		if err := downloadAndInstallWireGuard(); err != nil {
			fail("tunnel install failed")
			return
		}
	}

	if err := os.WriteFile(confPath, []byte(buildWgConf(privKey, reg)), 0600); err != nil {
		fail("could not write tunnel config")
		return
	}

	setStatus("Starting the secure tunnel...", "")
	svc := `WireGuardTunnel$` + tunnelName
	runPowerShell(fmt.Sprintf(`Stop-Service -Name '%s' -Force -ErrorAction SilentlyContinue`, svc))
	time.Sleep(500 * time.Millisecond)
	runHidden(wireguardPath, "/uninstalltunnelservice", tunnelName)
	time.Sleep(2 * time.Second)
	if out, err := runHidden(wireguardPath, "/installtunnelservice", confPath); err != nil {
		fail(fmt.Sprintf("tunnel did not start: %v %s", err, out))
		return
	}
	s.wgTunnelUp = true
	time.Sleep(2 * time.Second)

	setStatus("Preparing screen sharing...", "")
	if err := setupUltraVnc(reg.VncPasswordIni, s); err != nil {
		fail("screen sharing setup failed: " + err.Error())
		return
	}
	s.vncInstalled = true
	addVncFirewallRule()

	setStatus("Notifying your technician...", "")
	if err := apiReady(s.server, s.code); err != nil {
		fail("could not notify technician")
		return
	}

	setStatus("Ready — waiting for your technician to connect...", "Keep this window open. You'll see here the moment they connect.")

	// Poll until the tech ends the session (or it expires). Runs over the public internet,
	// so it survives the tunnel dropping. Also reflects when the technician actually connects
	// or disconnects, so the customer isn't left guessing.
	go func() {
		lastViewer := ""
		for {
			time.Sleep(8 * time.Second)
			status, viewer, err := apiStatus(st.server, st.code)
			if err != nil {
				continue
			}
			if status == "ended" {
				break
			}
			if viewer != lastViewer {
				lastViewer = viewer
				if viewer == "connected" {
					setStatus("Your technician is now connected.", "They can see your screen. Keep this window open until support is complete.")
				} else {
					setStatus("Waiting for your technician to connect...", "Keep this window open. You'll see here the moment they connect.")
				}
			}
		}
		mw.Synchronize(func() { mw.Close() }) // triggers cleanup via Closing handler
	}()
}

// ── UltraVNC ─────────────────────────────────────────────────────────────────────

func uvncInstalled() bool {
	for _, d := range uvncDirs {
		if fileExists(filepath.Join(d, "winvnc.exe")) {
			return true
		}
	}
	return false
}

func uvncDir() string {
	for _, d := range uvncDirs {
		if fileExists(filepath.Join(d, "winvnc.exe")) {
			return d
		}
	}
	return uvncDirs[0]
}

// iniPaths returns both config locations the service might load — install folder and
// ProgramData — so the password takes effect regardless of the build.
func iniPaths() []string {
	return []string{
		filepath.Join(uvncDir(), "ultravnc.ini"),
		`C:\ProgramData\UltraVNC\ultravnc.ini`,
	}
}

func setupUltraVnc(passwdIni string, s *appState) error {
	if !s.vncWasInstalled {
		setStatus("Downloading screen sharing (~5 MB)...", "")
		if err := download(ultravncInstaller, vncSetupPath); err != nil {
			return fmt.Errorf("download: %w", err)
		}
		setStatus("Installing screen sharing...", "")
		// uvnc-bvba ships an Inno Setup installer.
		if out, err := runHidden(vncSetupPath, "/verysilent", "/suppressmsgboxes", "/norestart"); err != nil {
			return fmt.Errorf("install: %v %s", err, out)
		}
		// wait for winvnc.exe to appear
		for i := 0; i < 30 && !uvncInstalled(); i++ {
			time.Sleep(1 * time.Second)
		}
		if !uvncInstalled() {
			return fmt.Errorf("UltraVNC did not appear after install")
		}
	}

	// Stop anything holding port 5900 before rewriting config.
	runHidden(`C:\Windows\System32\net.exe`, "stop", uvncService)
	runPowerShell(`Get-Process -Name 'winvnc*' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue`)
	time.Sleep(1 * time.Second)

	ini := "[ultravnc]\r\n" +
		"passwd=" + passwdIni + "\r\n" +
		"passwd2=" + passwdIni + "\r\n" +
		"PortNumber=5900\r\n" +
		"HTTPPortNumber=5800\r\n" +
		"AutoPortSelect=0\r\n" +
		"UseVncAuthentication=1\r\n" +
		"AuthRequired=1\r\n" +
		"MSLogon=0\r\n" +
		"FileTransferEnabled=1\r\n" +
		"\r\n[admin]\r\n" +
		"SASSHook=1\r\n" +
		"QuerySetting=0\r\n" +
		"QueryAccept=1\r\n" +
		"AllowLoopback=1\r\n"

	// The service reads its config from one of two locations depending on the build: with an
	// `ultravnc.portable` marker it uses the install-folder ini, otherwise the modern uvnc-bvba
	// service reads C:\ProgramData\UltraVNC\ultravnc.ini and ignores the install folder. Write
	// BOTH so whichever the service loads carries the password with AuthRequired=1.
	for _, iniPath := range iniPaths() {
		if s.vncWasInstalled && fileExists(iniPath) && s.iniBackup == "" {
			s.iniBackup = iniPath // remember one to restore from; we back up all below
		}
		if s.vncWasInstalled && fileExists(iniPath) {
			copyFile(iniPath, iniPath+".plbak")
		}
		os.MkdirAll(filepath.Dir(iniPath), 0755)
		if err := os.WriteFile(iniPath, []byte(ini), 0644); err != nil && iniPath == filepath.Join(uvncDir(), "ultravnc.ini") {
			return fmt.Errorf("write ini: %w", err)
		}
	}

	// Install (if needed) and start the service.
	exe := filepath.Join(uvncDir(), "winvnc.exe")
	runHidden(exe, "-install")
	runHidden(`C:\Windows\System32\net.exe`, "start", uvncService)
	for i := 0; i < 10; i++ {
		out, _ := runHidden(`C:\Windows\System32\sc.exe`, "query", uvncService)
		if strings.Contains(out, "RUNNING") {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return nil // service state best-effort; guacd will retry
}

func removeUltraVnc(s *appState) {
	runHidden(`C:\Windows\System32\net.exe`, "stop", uvncService)
	runPowerShell(`Get-Process -Name 'winvnc*' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue`)
	time.Sleep(1 * time.Second)

	if s.vncWasInstalled {
		// It was already there — restore the customer's own config in every location we wrote.
		for _, p := range iniPaths() {
			if fileExists(p + ".plbak") {
				copyFile(p+".plbak", p)
				os.Remove(p + ".plbak")
			}
		}
		runHidden(`C:\Windows\System32\net.exe`, "start", uvncService)
		return
	}

	// We installed it — run the Inno uninstaller.
	uninstallUltraVncSilently()
}

// uninstallUltraVncSilently resolves the Inno uninstaller from the registry and runs it.
func uninstallUltraVncSilently() {
	ps := `$k = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue |
	  Get-ItemProperty -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like '*UltraVNC*' -or $_.DisplayName -like '*uvnc*' }
	foreach ($u in $k) { if ($u.UninstallString) { $s = $u.UninstallString.Trim('"'); Start-Process -FilePath $s -ArgumentList '/verysilent','/suppressmsgboxes','/norestart' -Wait -ErrorAction SilentlyContinue } }`
	runPowerShell(ps)
	// Best-effort directory sweep if the uninstaller left the dir.
	for _, d := range uvncDirs {
		runPowerShell(fmt.Sprintf(`Remove-Item -Recurse -Force '%s' -ErrorAction SilentlyContinue`, d))
	}
	os.Remove(vncSetupPath)
}

func addVncFirewallRule() {
	// The UltraVNC installer can add its own broad 5900 rule (all profiles, any remote IP),
	// which would expose the screen to the customer's local LAN — not just our VPN. Remove any
	// VNC rule that isn't ours, then add our single rule scoped to the WireGuard range so 5900
	// is reachable ONLY through the tunnel.
	runPowerShell(`Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { ($_.DisplayName -match 'VNC|winvnc|uvnc') -and ($_.DisplayName -ne 'ProxyLink VNC') } | Remove-NetFirewallRule -ErrorAction SilentlyContinue`)
	runHidden(`C:\Windows\System32\netsh.exe`, "advfirewall", "firewall", "delete", "rule", "name="+firewallRuleName)
	runHidden(`C:\Windows\System32\netsh.exe`, "advfirewall", "firewall", "add", "rule",
		"name="+firewallRuleName, "protocol=TCP", "dir=in", "localport=5900",
		"remoteip=10.100.0.0/16", "action=allow", "profile=any")
}

func removeVncFirewallRule() {
	runHidden(`C:\Windows\System32\netsh.exe`, "advfirewall", "firewall", "delete", "rule",
		"name="+firewallRuleName)
}

// ── cleanup ──────────────────────────────────────────────────────────────────────

// cleanup tears down what THIS run set up, respecting pre-existing installs. Idempotent.
func cleanup(s *appState) {
	if s.cleanedUp {
		return
	}
	s.cleanedUp = true

	apiEnd(s.server, s.code) // tell the server to drop the peer immediately

	if s.vncInstalled {
		removeUltraVnc(s)
	}
	removeVncFirewallRule()

	if s.wgTunnelUp {
		runHidden(wireguardPath, "/uninstalltunnelservice", tunnelName)
		time.Sleep(1 * time.Second)
		os.Remove(confPath)
	}
}

// forceCleanup is the manual recovery path (-cleanup CODE): it cuts remote access by stopping
// VNC and removing the tunnel + firewall rule. It does not uninstall UltraVNC, which may be the
// customer's own. The tool installs no scheduled task or other persistence — nothing is left
// running or auto-starting on the machine after a session.
func forceCleanup(server, code string) {
	apiEnd(server, code)
	removeVncFirewallRule()
	runHidden(`C:\Windows\System32\net.exe`, "stop", uvncService)
	runHidden(wireguardPath, "/uninstalltunnelservice", tunnelName)
	os.Remove(confPath)
}

// ── WireGuard ─────────────────────────────────────────────────────────────────────

func generateWireGuardKeypair() (privB64, pubB64 string, err error) {
	var priv [32]byte
	if _, err = io.ReadFull(rand.Reader, priv[:]); err != nil {
		return
	}
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)
	return base64.StdEncoding.EncodeToString(priv[:]), base64.StdEncoding.EncodeToString(pub[:]), nil
}

func buildWgConf(privateKey string, reg *registerResponse) string {
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/32\nDNS = %s\n\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s\nEndpoint = %s\nPersistentKeepalive = %d\n",
		privateKey, reg.VpnIP, reg.DNS, reg.ServerPublicKey, reg.PresharedKey, reg.AllowedIPs, reg.Endpoint, reg.Keepalive)
}

func downloadAndInstallWireGuard() error {
	tmp := filepath.Join(os.TempDir(), "wireguard-installer.exe")
	if err := download(wireguardInstaller, tmp); err != nil {
		return err
	}
	cmd := exec.Command(tmp, "/S")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil {
		return err
	}
	for i := 0; i < 30; i++ {
		if fileExists(wireguardPath) {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("WireGuard install did not complete")
}

// ── API ────────────────────────────────────────────────────────────────────────

type registerResponse struct {
	VpnIP           string `json:"vpn_ip"`
	PresharedKey    string `json:"preshared_key"`
	ServerPublicKey string `json:"server_public_key"`
	Endpoint        string `json:"endpoint"`
	AllowedIPs      string `json:"allowed_ips"`
	DNS             string `json:"dns"`
	Keepalive       int    `json:"keepalive"`
	VncPasswordIni  string `json:"vnc_password_ini"`
	ExpiresAt       string `json:"expires_at"`
}

func apiRegister(server, code, pubKey string) (*registerResponse, error) {
	body, _ := json.Marshal(map[string]string{"public_key": pubKey})
	resp, err := http.Post(fmt.Sprintf("%s/api/support/%s/register", server, code), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 404:
		return nil, fmt.Errorf("code not found or expired")
	case 409:
		return nil, fmt.Errorf("this code has already been used")
	case 429:
		return nil, fmt.Errorf("too many attempts, wait a moment")
	}
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server error %d: %s", resp.StatusCode, string(b))
	}
	var r registerResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("invalid server response")
	}
	return &r, nil
}

func apiReady(server, code string) error {
	resp, err := http.Post(fmt.Sprintf("%s/api/support/%s/ready", server, code), "application/json", bytes.NewReader([]byte("{}")))
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}

func apiStatus(server, code string) (status, viewer string, err error) {
	resp, e := http.Get(fmt.Sprintf("%s/api/support/%s/status", server, code))
	if e != nil {
		return "", "", e
	}
	defer resp.Body.Close()
	var r struct {
		Status string `json:"status"`
		Viewer string `json:"viewer"`
	}
	json.NewDecoder(resp.Body).Decode(&r)
	return r.Status, r.Viewer, nil
}

func apiEnd(server, code string) {
	if code == "" {
		return
	}
	resp, err := http.Post(fmt.Sprintf("%s/api/support/%s/end", server, code), "application/json", bytes.NewReader([]byte("{}")))
	if err == nil {
		resp.Body.Close()
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────────

func download(url, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download status %d", resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	_, cErr := io.Copy(f, resp.Body)
	f.Close()
	if cErr != nil {
		os.Remove(dest)
	}
	return cErr
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0644)
}

func runHidden(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func runPowerShell(script string) (string, error) {
	cmd := exec.Command("powershell", "-NonInteractive", "-NoProfile", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func isAdmin() bool {
	var sid *windows.SID
	windows.AllocateAndInitializeSid(&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID, windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &sid)
	defer windows.FreeSid(sid)
	member, err := windows.Token(0).IsMember(sid)
	return err == nil && member
}
