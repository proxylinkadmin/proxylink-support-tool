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
//
// ⚠️ THE GOVERNING RULE OF THIS FILE (same one the Windows deploy follows):
// if a VNC server, a firewall rule or a config file was here before we arrived, it is the
// customer's and we put it back exactly as we found it. If we created it, we remove it.
// Ownership is decided ONCE, on first contact, and recorded — never re-probed, because after
// we have installed something the machine can no longer tell us who installed it.

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lxn/walk"
	dcl "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
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

	// ⚠️ PINNED. This is the SHA-256 of public/assets/ultravnc-setup.exe on app.proxylink.dev.
	// The tool runs this installer as Administrator, so it verifies the bytes before executing
	// them rather than trusting whatever the URL happens to serve. If that asset is ever
	// replaced, this constant must be updated and the tool rebuilt and re-signed, or every
	// session on a PC without UltraVNC will stop at "screen sharing setup failed".
	ultravncInstallerSHA256 = "434853e116eeb132cfdf47fdf6ba489d30c67a38147aff6b9bd0ec2f4d0f1919"

	tunnelName       = "plsupport"
	defaultUvncSvc   = "uvnc_service"
	firewallRuleName = "ProxyLink VNC"

	// Our own working directory. Everything we download and then execute as Administrator,
	// plus the WireGuard config that carries a private key, lives here and NOT in
	// C:\Windows\Temp, where any logged-in user can pre-create a file for us to truncate and
	// then run with full privileges. Created with inheritance stripped and only
	// Administrators + SYSTEM granted access. See lockDownPath.
	workDir = `C:\ProgramData\ProxyLinkSupport`

	// Paths used by builds up to and including v4. Kept only so this build can finish
	// cleaning up after one of them; nothing new is ever written to them.
	legacyVncSetupPath = `C:\Windows\Temp\plsupport-uvnc.exe`
	legacyConfPath     = `C:\Windows\Temp\plsupport.conf`
	legacyStatePath    = `C:\Windows\Temp\plsupport.state`

	// The maximum life of a session if the server never tells us it ended: a backstop for
	// the case where the machine loses the internet and every status poll fails. The server's
	// own expiry, when we have it, is usually much shorter and wins.
	maxSessionLife = 4 * time.Hour
)

var (
	vncSetupPath = filepath.Join(workDir, "uvnc-setup.exe")
	confPath     = filepath.Join(workDir, tunnelName+".conf")
	// The list of firewall rules that existed BEFORE we ran the UltraVNC installer. See
	// addVncFirewallRule: a rule that appeared while we were installing is ours to remove,
	// and a rule that was already there is the customer's, whatever it is called.
	fwSnapshotPath = filepath.Join(workDir, "firewall-before.txt")
	// Written the moment a session starts changing the machine, deleted when cleanup
	// finishes. Its presence at startup means a previous run never cleaned up.
	statePath = filepath.Join(workDir, "session.json")
)

// WireGuard keeps an encrypted copy of every installed tunnel config. Uninstalling the
// tunnel service does not remove it, so without this the customer is left with a permanent
// "plsupport" entry in their WireGuard UI after every support session.
var wgLeftovers = []string{
	`C:\Program Files\WireGuard\Data\Configurations\` + tunnelName + `.conf.dpapi`,
	filepath.Join(os.Getenv("ProgramData"), "WireGuard", tunnelName+".conf"),
}

// UltraVNC install locations to probe (uvnc-bvba installer).
var uvncDirs = []string{
	`C:\Program Files\uvnc bvba\UltraVNC`,
	`C:\Program Files (x86)\uvnc bvba\UltraVNC`,
}

// HTTP clients. Neither may use http.DefaultClient, which has no timeout at all: a
// black-holed connection would hang the flow forever with both controls disabled, and the
// only way out for the customer is End Task — which is precisely the interrupted teardown
// that leaves our password on their machine.
var (
	apiClient      = &http.Client{Timeout: 20 * time.Second}
	downloadClient = &http.Client{Timeout: 10 * time.Minute}
)

// ── shared runtime state ────────────────────────────────────────────────────────

// persistedState is what survives to the next launch. It is the record of what this machine
// looked like before we touched it; without it a crashed session cannot be undone correctly.
type persistedState struct {
	VncWasInstalled bool   `json:"vnc_was_installed"`
	WgWasInstalled  bool   `json:"wg_was_installed"`
	UvncDir         string `json:"uvnc_dir"`
	UvncService     string `json:"uvnc_service"`
}

type appState struct {
	mu sync.Mutex

	server string
	code   string

	// Ownership, decided once (see probed) and never re-derived.
	probed          bool
	vncWasInstalled bool // UltraVNC already present before we touched it
	wgWasInstalled  bool
	uvncDir         string
	uvncService     string

	vncTouched bool // we have begun installing/configuring VNC this run
	wgTouched  bool // we have begun installing/configuring the tunnel this run

	// How much longer the session may run, measured from registration. A DURATION, never an
	// absolute time: see sessionLifeFrom.
	sessionLife time.Duration

	cleaning  bool
	cleanedUp bool

	// Held for the whole of runFlow so that closing the window mid-install waits for the
	// install to finish rather than tearing down underneath it.
	flow sync.WaitGroup
}

func (s *appState) snapshot() persistedState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return persistedState{
		VncWasInstalled: s.vncWasInstalled,
		WgWasInstalled:  s.wgWasInstalled,
		UvncDir:         s.uvncDir,
		UvncService:     s.uvncService,
	}
}

func (s *appState) isCleaning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cleaning || s.cleanedUp
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
			// ⚠️ NOT free-form. The server named here decides who the consent dialog says is
			// calling, what Endpoint the tunnel dials, and what password guards the screen —
			// so an attacker who can choose it can author the whole trust story while our
			// signed binary vouches for it. Only ProxyLink's own hosts over HTTPS.
			if v, ok := allowedServer(strings.TrimPrefix(a, "-server=")); ok {
				st.server = v
			}
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
		AssignTo:   &mw,
		Title:      "ProxyLink Support",
		Icon:       winIcon,
		MinSize:    dcl.Size{Width: 480, Height: 320},
		Size:       dcl.Size{Width: 480, Height: 320},
		Layout:     dcl.VBox{Margins: dcl.Margins{Left: 24, Top: 20, Right: 24, Bottom: 20}, Spacing: 8},
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
	//
	// ⚠️ ORDER MATTERS AND IS NOT COSMETIC. `cleaning` must be tested BEFORE `cleanedUp`.
	// cleanup() begins by telling the server the session has ended; the status poll sees
	// "ended" 8 seconds later and calls Close(). If that Close is allowed through while
	// teardown is still running, the process exits mid-cleanup and the customer keeps our
	// session password in their ultravnc.ini with the service running. Teardown routinely
	// takes longer than 8 seconds — an UltraVNC uninstall always does. This is the everyday
	// path, not an attack.
	mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		st.mu.Lock()
		cleaning, done := st.cleaning, st.cleanedUp
		if !cleaning && !done {
			st.cleaning = true
		}
		st.mu.Unlock()

		if cleaning {
			*canceled = true // teardown in progress: it decides when we close, not the poll
			return
		}
		if done {
			return // cleanup finished — allow the window to close
		}

		*canceled = true
		// ⚠️ Take the controls away for good. After a failed attempt fail() re-enables them,
		// and a customer who then closes the window can still click Connect while teardown is
		// running: a second runFlow would reinstall UltraVNC and rewrite the ini while cleanup
		// removes them, and its WaitGroup.Add would race cleanup's Wait, which Go documents as
		// misuse and which can panic the process mid-teardown — the exact failure this whole
		// change exists to prevent.
		codeEdit.SetEnabled(false)
		connectBtn.SetEnabled(false)
		setStatus("Ending session — cleaning up...", "Removing screen sharing and the secure tunnel. This takes a few seconds.")
		go func() {
			cleanup(st)
			mw.Synchronize(func() {
				setStatus("Support session ended.", "Everything has been removed. You can close this window.")
				mw.Close()
			})
		}()
	})

	// Finish any session that died without cleaning up (see recoverPreviousSession). It
	// can take a few seconds — an UltraVNC uninstall is involved — so it runs off the UI
	// thread with Connect disabled, rather than freezing the window on launch. The common
	// case is that there is nothing to do and this is over instantly.
	//
	// ⚠️ Only when elevated. Every step of it — icacls, net stop, the uninstaller — silently
	// fails without admin, and it would report success by saying nothing. The new marker sits
	// inside a folder a standard user cannot even stat, but a leftover from a v4 build lives
	// in C:\Windows\Temp where anyone can see it. Leaving the marker alone means the next
	// elevated launch still finds it and finishes the job properly.
	if (fileExists(statePath) || fileExists(legacyStatePath)) && isAdmin() {
		connectBtn.SetEnabled(false)
		setStatus("Finishing an interrupted session...", "The last support session did not close properly. Putting this PC back as it was.")
		go func() {
			recoverPreviousSession()
			mw.Synchronize(func() {
				connectBtn.SetEnabled(true)
				setStatus("", "You can close this window at any time to end support.")
				if preCode != "" {
					connectBtn.SetFocus()
				} else {
					codeEdit.SetFocus()
				}
			})
		}()
	} else if preCode != "" {
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
	if st.isCleaning() {
		return // teardown owns the machine until it finishes
	}
	st.code = code
	codeEdit.SetEnabled(false)
	connectBtn.SetEnabled(false)

	// ⚠️ ASK WHO, AND ASK THE CUSTOMER, BEFORE TOUCHING THE MACHINE.
	//
	// The download page is public: anyone can be talked into fetching this tool and typing
	// a code read to them over the telephone. That is the tech-support scam, word for word,
	// and it is the flow TeamViewer and AnyDesk are used for. The single thing a criminal
	// cannot fake is OUR record of which technician opened the session — so we fetch the
	// name from the server and make the customer agree to that specific person by name.
	//
	// Fails CLOSED. If we cannot say who is on the other end, we do not connect: a guard
	// that can be skipped by blocking one request is not a guard.
	setStatus("Checking who is asking to connect...", "")
	go func() {
		who, err := apiWho(st.server, code)
		if err != nil {
			mw.Synchronize(func() {
				setStatus("Could not check this code: "+err.Error(), "Nothing has been changed on this computer. Check the code with your technician and try again.")
				codeEdit.SetEnabled(true)
				connectBtn.SetEnabled(true)
			})
			return
		}
		mw.Synchronize(func() {
			// Re-check: the customer may have closed the window while we were asking the
			// server who is calling, and the dialog itself is answered at human speed.
			if st.isCleaning() {
				return
			}
			if !confirmTechnician(who) {
				setStatus("Cancelled — nothing was changed on this computer.", "If you did not expect this, tell your IT provider.")
				codeEdit.SetEnabled(true)
				connectBtn.SetEnabled(true)
				return
			}
			if st.isCleaning() {
				return
			}
			st.flow.Add(1)
			go runFlow(st)
		})
	}()
}

// confirmTechnician shows the customer who is asking and waits for a yes.
//
// Deliberately NOT a friendly "Connect?" prompt. It leads with the one question that works
// no matter whose name appears — did YOU make this call? — because the scam depends entirely
// on the customer not having called anyone. The name is presented as a CLAIM ("someone who
// says they are"), never as a credential: signup is open, so the name is chosen by whoever
// opened the session, and our signed binary must not be read as vouching for it.
//
// There is deliberately no "we have not verified this name" warning and no account-age line.
// A caution shown in every legitimate session is read by nobody and frightens the 99.9% who
// are fine; and an age line's absence would itself read as an endorsement.
//
// The safe answer is the default: the dialog's No button is what Escape and the close box
// both pick, because a person clicking through a dialog they do not understand should end
// up not connected.
//
// ⚠️ THE QUESTION NAMES THE MSP, NOT US. It used to ask "did you contact ProxyLink support
// yourself?" and that is a question about a company the customer has never heard of. They do
// not call ProxyLink; they call Powertech, or they call Mitsos. A safety question the person
// cannot answer from certain knowledge is not a safety question, it is a dialog they click
// through — so it has to be phrased in the terms of the call they actually remember making.
func confirmTechnician(who *whoResponse) bool {
	from := who.Technician
	if who.Company != "" {
		from = fmt.Sprintf("%s (%s)", who.Technician, who.Company)
	}

	// Who the customer thinks they rang: their provider's company if we know it, otherwise the
	// engineer by name (a one-man MSP is a name, not a company), otherwise a generic phrasing.
	// The server already defaults the technician to "your IT provider", which reads correctly
	// in this sentence on its own.
	called := strings.TrimSpace(who.Company)
	if called == "" {
		called = strings.TrimSpace(who.Technician)
	}
	lead := "Did you call for IT support yourself?"
	if called != "" {
		lead = fmt.Sprintf("Did you call %s yourself?", called)
	}

	msg := fmt.Sprintf(
		"%s\n\n"+
			"Someone who says they are\n"+
			"    %s\n"+
			"is asking to see this computer's screen.\n\n"+
			"Press Yes only if YOU called them and they are expecting you.\n\n"+
			"If someone called you out of the blue, about a virus, your bank, "+
			"or Microsoft, press No.",
		lead, from)

	return walk.MsgBox(mw, "Allow this connection?", msg,
		walk.MsgBoxYesNo|walk.MsgBoxIconWarning|walk.MsgBoxDefButton2) == win.IDYES
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
	defer s.flow.Done()

	if err := prepareWorkDir(); err != nil {
		fail("could not prepare a private working folder")
		return
	}

	// ⚠️ Ownership is decided ONCE and then remembered for the life of the process.
	// A failed attempt leaves the Connect button live, and by the time the customer clicks
	// it again UltraVNC may be on the machine because WE put it there. Re-probing at that
	// point reads "already installed", the tool concludes it is the customer's, and it is
	// never uninstalled again: their PC keeps a VNC server running at boot with our session
	// password. The machine cannot tell us who installed something after we installed it.
	s.mu.Lock()
	if !s.probed {
		s.vncWasInstalled = uvncInstalled()
		s.wgWasInstalled = fileExists(wireguardPath)
		s.uvncDir = uvncDir()
		s.uvncService = uvncServiceName(s.uvncDir)
		s.probed = true
	}
	s.mu.Unlock()
	// Record what we found BEFORE changing anything, so a run that never reaches cleanup
	// can still be undone correctly by the next launch. See recoverPreviousSession.
	writeState(s)

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
	s.mu.Lock()
	s.sessionLife = sessionLifeFrom(reg)
	s.mu.Unlock()

	if !s.wgWasInstalled {
		setStatus("Installing the secure tunnel (one-time, ~10 MB)...", "")
		if err := downloadAndInstallWireGuard(); err != nil {
			fail("tunnel install failed")
			return
		}
	}

	// ⚠️ Set BEFORE the machine is modified, not after. A failure part-way through leaves
	// real changes behind, and a flag set only on success tells cleanup there is nothing to
	// undo — which is how a half-finished session used to become permanent damage.
	s.mu.Lock()
	s.wgTouched = true
	s.mu.Unlock()

	if err := os.WriteFile(confPath, []byte(buildWgConf(privKey, reg)), 0600); err != nil {
		fail("could not write tunnel config")
		return
	}
	lockDownPath(confPath, false)

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
	time.Sleep(2 * time.Second)

	setStatus("Preparing screen sharing...", "")
	if err := setupUltraVnc(reg.VncPasswordIni, s); err != nil {
		fail("screen sharing setup failed: " + err.Error())
		return
	}
	addVncFirewallRule(s, reg.AllowedIPs)

	setStatus("Notifying your technician...", "")
	if err := apiReady(s.server, s.code); err != nil {
		fail("could not notify technician")
		return
	}

	setStatus("Ready — waiting for your technician to connect...", "Keep this window open. You'll see here the moment they connect.")

	go pollUntilEnded(s)
}

// pollUntilEnded watches the session over the public internet, so it survives the tunnel
// dropping. It also reflects when the technician actually connects or disconnects, so the
// customer isn't left guessing.
//
// ⚠️ It carries the local expiry backstop. Every status request failing — the machine loses
// its internet, or the server is unreachable — used to mean the loop span forever and the
// session never ended by itself. A session has a lifetime whether or not we can ask about it.
func pollUntilEnded(s *appState) {
	s.mu.Lock()
	life := s.sessionLife
	s.mu.Unlock()
	if life <= 0 || life > maxSessionLife {
		life = maxSessionLife
	}
	deadline := time.Now().Add(life)

	lastViewer := ""
	for {
		time.Sleep(8 * time.Second)
		if s.isCleaning() {
			return // teardown already under way; it will close the window itself
		}
		if time.Now().After(deadline) {
			break
		}
		status, viewer, err := apiStatus(s.server, s.code)
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
}

// sessionLifeFrom turns the server's absolute expiry into how much longer the session has
// to run, and it does the subtraction in the SERVER's clock, not this machine's.
//
// ⚠️ Never compare the server's expiry against the endpoint's local time. Consumer PCs run
// with wildly wrong clocks, and a machine 45 minutes fast would read a 30-minute session as
// already expired and tear the whole thing down about eight seconds after "Ready", while the
// technician was still connecting. The Date header on the same response is the server saying
// what time IT thinks it is, so expiry minus that is a duration both clocks agree on. Falls
// back to the 4h backstop whenever anything is missing or nonsensical.
func sessionLifeFrom(reg *registerResponse) time.Duration {
	expires := parseTime(reg.ExpiresAt)
	if expires.IsZero() || reg.serverNow.IsZero() {
		return 0
	}
	life := expires.Sub(reg.serverNow)
	if life <= 0 {
		return 0
	}
	return life
}

func parseTime(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z0700", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t
		}
	}
	return time.Time{}
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

// uvncServiceName resolves the service that actually runs winvnc.exe out of the install
// folder we are working with, instead of assuming the uvnc-bvba default. Older builds
// register the service as "winvnc" and a renamed service would otherwise be left running
// with our password while we "stopped" a service that does not exist.
func uvncServiceName(dir string) string {
	out, err := runPowerShell(fmt.Sprintf(
		`Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | `+
			`Where-Object { $_.PathName -like '*%s*' } | `+
			`Select-Object -First 1 -ExpandProperty Name`, psEscape(dir)))
	if err == nil {
		if name := strings.TrimSpace(out); name != "" && !strings.ContainsAny(name, "\r\n") {
			return name
		}
	}
	return defaultUvncSvc
}

// iniPaths returns both config locations the service might load — install folder and
// ProgramData — so the password takes effect regardless of the build.
func iniPaths(dir string) []string {
	if dir == "" {
		dir = uvncDir()
	}
	return []string{
		filepath.Join(dir, "ultravnc.ini"),
		`C:\ProgramData\UltraVNC\ultravnc.ini`,
	}
}

func setupUltraVnc(passwdIni string, s *appState) error {
	// ⚠️ Before the first byte changes, not after this function returns successfully.
	// Everything below modifies the machine; an error return with the flag unset told
	// cleanup there was nothing to undo, and the state file was then deleted, making the
	// damage permanent and invisible.
	s.mu.Lock()
	s.vncTouched = true
	dir, service, preexisting := s.uvncDir, s.uvncService, s.vncWasInstalled
	s.mu.Unlock()

	if !preexisting {
		// Record the firewall as we found it, before the installer adds anything to it.
		snapshotFirewallRules()
		setStatus("Downloading screen sharing (~5 MB)...", "")
		if err := download(ultravncInstaller, vncSetupPath); err != nil {
			return fmt.Errorf("download: %w", err)
		}
		// We are about to run this as Administrator. Verify the bytes are the ones we
		// published before executing them.
		if err := verifySHA256(vncSetupPath, ultravncInstallerSHA256); err != nil {
			os.Remove(vncSetupPath)
			return err
		}
		setStatus("Installing screen sharing...", "")
		// uvnc-bvba ships an Inno Setup installer.
		if out, err := runHiddenFor(5*time.Minute, vncSetupPath, "/verysilent", "/suppressmsgboxes", "/norestart"); err != nil {
			return fmt.Errorf("install: %v %s", err, out)
		}
		// wait for winvnc.exe to appear
		for i := 0; i < 30 && !uvncInstalled(); i++ {
			time.Sleep(1 * time.Second)
		}
		if !uvncInstalled() {
			return fmt.Errorf("UltraVNC did not appear after install")
		}
		// The install decided the real paths; re-resolve now that they exist.
		dir = uvncDir()
		service = uvncServiceName(dir)
		s.mu.Lock()
		s.uvncDir, s.uvncService = dir, service
		s.mu.Unlock()
		writeState(s)
	}

	// ⚠️ Last chance to notice the session ended while the installer was running. Past this
	// point we write the password and start the service; doing that after teardown has run
	// leaves exactly what teardown existed to remove.
	if s.isCleaning() {
		return fmt.Errorf("session ended during setup")
	}

	// Stop anything holding port 5900 before rewriting config.
	stopUvnc(dir, service)

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
		// ⚠️ 0, not 1. UltraVNC stores the session password reversibly under a key that is
		// public knowledge, so anyone who can read the ini can recover it. Allowing loopback
		// turned that into a working local privilege escalation: any signed-in user reads the
		// file, decodes the password and connects to 127.0.0.1:5900 with full control of the
		// console. The technician arrives over the VPN, never over loopback, so nothing
		// legitimate needs this. The ini is locked down as well, below.
		"AllowLoopback=0\r\n"

	// The service reads its config from one of two locations depending on the build: with an
	// `ultravnc.portable` marker it uses the install-folder ini, otherwise the modern uvnc-bvba
	// service reads C:\ProgramData\UltraVNC\ultravnc.ini and ignores the install folder. Write
	// BOTH so whichever the service loads carries the password with AuthRequired=1.
	primary := filepath.Join(dir, "ultravnc.ini")
	for _, iniPath := range iniPaths(dir) {
		// ⚠️ Back up whatever is already here, whoever put it there, and NEVER overwrite an
		// existing backup: a second session (or a retry) would otherwise copy OUR ini over
		// the customer's only saved copy of theirs, and the restore at the end would put our
		// session password back rather than their settings.
		if fileExists(iniPath) && !fileExists(iniPath+".plbak") {
			if err := copyFile(iniPath, iniPath+".plbak"); err != nil && iniPath == primary {
				return fmt.Errorf("back up ini: %w", err)
			}
		}
		// If the config directory is not there we are creating it, so it is ours to own and
		// lock. If it already exists it is the customer's and we leave its permissions alone.
		if parent := filepath.Dir(iniPath); !fileExists(parent) {
			if os.MkdirAll(parent, 0700) == nil {
				takeOwnership(parent)
				lockDownPath(parent, true)
			}
		}
		// Remove first, then create exclusively: the same hardening download() uses, so we
		// never write our password through a file or link somebody else left at this path.
		if err := writeFileExclusive(iniPath, []byte(ini)); err != nil && iniPath == primary {
			return fmt.Errorf("write ini: %w", err)
		}
		lockDownPath(iniPath, false)
	}

	// Install (if needed) and start the service.
	if s.isCleaning() {
		return fmt.Errorf("session ended during setup")
	}
	runHidden(filepath.Join(dir, "winvnc.exe"), "-install")
	if service == "" {
		service = uvncServiceName(dir)
		s.mu.Lock()
		s.uvncService = service
		s.mu.Unlock()
	}
	runHidden(`C:\Windows\System32\net.exe`, "start", service)
	for i := 0; i < 10; i++ {
		out, _ := runHidden(`C:\Windows\System32\sc.exe`, "query", service)
		if strings.Contains(out, "RUNNING") {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return nil // service state best-effort; guacd will retry
}

// stopUvnc stops the VNC service and kills only the winvnc processes running out of the
// install folder we are managing. The old wildcard kill took down any UltraVNC anywhere on
// the machine, including one in a folder we never look at and therefore never restore.
func stopUvnc(dir, service string) {
	if service == "" {
		service = defaultUvncSvc
	}
	runHidden(`C:\Windows\System32\net.exe`, "stop", service)
	runPowerShell(fmt.Sprintf(
		`Get-Process -Name 'winvnc*' -ErrorAction SilentlyContinue | `+
			`Where-Object { $_.Path -like '%s\*' } | `+
			`Stop-Process -Force -ErrorAction SilentlyContinue`, psEscape(dir)))
	time.Sleep(1 * time.Second)
}

func removeUltraVnc(s *appState) {
	snap := s.snapshot()
	// Prefer the folder we recorded, but not if UltraVNC is not actually in it. A session that
	// died between the download and the post-install re-resolve persisted the default 64-bit
	// path; if the installer had put UltraVNC under Program Files (x86), the scoped uninstall
	// would match nothing and our copy would be left installed and running.
	dir := snap.UvncDir
	if dir == "" || !fileExists(filepath.Join(dir, "winvnc.exe")) {
		if uvncInstalled() {
			dir = uvncDir()
		} else if dir == "" {
			dir = uvncDirs[0]
		}
	}
	stopUvnc(dir, snap.UvncService)

	// Put every config back the way we found it. A file we backed up is restored; a file
	// that was not there before this session is ours and goes. Previously only backed-up
	// files were handled, so an ini we created — carrying our session password — was left
	// on the machine forever, in a folder the uninstaller does not clean.
	restored := false
	for _, p := range iniPaths(dir) {
		if fileExists(p + ".plbak") {
			os.Remove(p)
			if copyFile(p+".plbak", p) == nil {
				restored = true
			}
			os.Remove(p + ".plbak")
			continue
		}
		os.Remove(p)
	}

	if snap.VncWasInstalled {
		// ⚠️ Only restart the service when we actually gave the customer their own config
		// back. With no backup to restore we have just deleted the only ini on the machine,
		// and starting the service now would leave a VNC server running with no password at
		// all — worse than leaving it stopped. A stopped service is something they can start
		// again; an unauthenticated one is an open door they cannot see.
		if restored {
			svc := snap.UvncService
			if svc == "" {
				svc = defaultUvncSvc
			}
			runHidden(`C:\Windows\System32\net.exe`, "start", svc)
		}
		return
	}

	// We installed it — run the Inno uninstaller.
	uninstallUltraVncSilently(dir)
}

// uninstallUltraVncSilently resolves the Inno uninstaller from the registry and runs it.
//
// ⚠️ Scoped to the folder we installed into. Matching on DisplayName alone removed any
// UltraVNC-ish entry on the machine, which is broader than the two paths we look at when
// deciding whether UltraVNC was already here: a customer copy installed somewhere else was
// invisible to the check and uninstallable by the sweep.
func uninstallUltraVncSilently(dir string) {
	ps := fmt.Sprintf(`$dir = '%s'
	$k = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue |
	  Get-ItemProperty -ErrorAction SilentlyContinue |
	  Where-Object { ($_.DisplayName -like '*UltraVNC*' -or $_.DisplayName -like '*uvnc*') -and
	                 (($_.InstallLocation -and $_.InstallLocation.TrimEnd('\') -eq $dir) -or
	                  ($_.UninstallString -and $_.UninstallString.Replace('"','') -like ($dir + '\*'))) }
	foreach ($u in $k) { if ($u.UninstallString) { $s = $u.UninstallString.Trim('"'); Start-Process -FilePath $s -ArgumentList '/verysilent','/suppressmsgboxes','/norestart' -Wait -ErrorAction SilentlyContinue } }`, psEscape(dir))
	runPowerShellFor(5*time.Minute, ps)
	// Best-effort: remove the install folder if the uninstaller left it, and the ProgramData
	// config folder, which the uninstaller never touches.
	runPowerShell(fmt.Sprintf(`Remove-Item -Recurse -Force '%s' -ErrorAction SilentlyContinue`, psEscape(dir)))
	os.Remove(`C:\ProgramData\UltraVNC\ultravnc.ini`)
	os.Remove(`C:\ProgramData\UltraVNC`) // only succeeds if empty, which is what we want
	os.Remove(vncSetupPath)
	os.Remove(legacyVncSetupPath)
}

func addVncFirewallRule(s *appState, allowedIPs string) {
	snap := s.snapshot()

	// ⚠️ Only sweep when WE installed UltraVNC, and only rules that belong to the copy we
	// installed. Its installer adds its own broad 5900 rule (all profiles, any remote IP)
	// which would expose the screen to the whole LAN rather than just our VPN, and that rule
	// is ours to clean up because we caused it.
	//
	// The guard is "no winvnc.exe in the two uvnc-bvba folders", but the old sweep deleted
	// every rule whose name merely matched VNC|winvnc|uvnc — so a customer running RealVNC,
	// TightVNC or TigerVNC (17 TightVNC machines in the fleet) lost their own rules
	// permanently, with nothing recorded anywhere to put them back. Matching on the rule's
	// program path is a POSITIVE ownership signal: it can only hit binaries in the folder we
	// installed. Same shape as the marker the Windows deploy uses.
	//
	// When the VNC server was ALREADY here, its firewall rules are the customer's own and we
	// leave them completely alone. Their exposure is their decision and it was exactly this
	// wide before we arrived — adding a VPN-scoped rule alongside widens nothing.
	if !snap.VncWasInstalled && fileExists(fwSnapshotPath) {
		dir := snap.UvncDir
		if dir == "" {
			dir = uvncDir()
		}
		// Two conditions, both required. The rule must have APPEARED while we were installing
		// (it is not in the before-list), and it must either point at a binary in the folder we
		// installed into or open a VNC port. A rule that predates us is the customer's whatever
		// it is called, and a rule we caused is ours whatever shape the vendor gave it —
		// program-based or port-based, which is not something we get to assume.
		runPowerShell(fmt.Sprintf(`$before = @{}
		Get-Content -LiteralPath '%s' -ErrorAction SilentlyContinue | ForEach-Object { $n = $_.Trim(); if ($n) { $before[$n] = $true } }
		if ($before.Count -gt 0) {
		  $dir = '%s'
		  Get-NetFirewallRule -ErrorAction SilentlyContinue |
		    Where-Object { $_.DisplayName -ne '%s' -and -not $before.ContainsKey($_.Name) } | ForEach-Object {
		      $r = $_; $mine = $false
		      $p = ($r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program
		      if ($p -and ($p -like ($dir + '\*'))) { $mine = $true }
		      if (-not $mine) {
		        $pf = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
		        if ($pf -and (($pf.LocalPort -contains '5900') -or ($pf.LocalPort -contains '5800'))) { $mine = $true }
		      }
		      if ($mine) { $r | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
		    }
		}`, psEscape(fwSnapshotPath), psEscape(dir), firewallRuleName))
	}

	// ⚠️ Scope the rule to the one address that ever connects. The server hands us the peer
	// it will reach us from (10.100.0.1/32); the rule used to allow the whole 10.100.0.0/16,
	// which on a customer LAN numbered inside that range opened the screen to their entire
	// network for the length of the session.
	remote := strings.TrimSpace(allowedIPs)
	if !validRemoteIP(remote) {
		remote = "10.100.0.1/32"
	}
	runHidden(`C:\Windows\System32\netsh.exe`, "advfirewall", "firewall", "delete", "rule", "name="+firewallRuleName)
	runHidden(`C:\Windows\System32\netsh.exe`, "advfirewall", "firewall", "add", "rule",
		"name="+firewallRuleName, "protocol=TCP", "dir=in", "localport=5900",
		"remoteip="+remote, "action=allow", "profile=any")
}

// snapshotFirewallRules records the unique Name of every firewall rule currently on the
// machine. Best-effort: if it fails, the file is absent and the sweep does not run at all,
// which leaves the installer's own rule in place for the session rather than risking the
// deletion of a rule that was never ours. Losing a customer's firewall rule is permanent;
// leaving one of ours for a few minutes is not.
func snapshotFirewallRules() {
	out, err := runPowerShell(`Get-NetFirewallRule -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name`)
	if err != nil || strings.TrimSpace(out) == "" {
		os.Remove(fwSnapshotPath)
		return
	}
	if err := os.WriteFile(fwSnapshotPath, []byte(out), 0600); err == nil {
		lockDownPath(fwSnapshotPath, false)
	}
}

// validRemoteIP accepts a single IP or CIDR, which is all the server ever sends and all
// netsh should ever be handed from a network response.
func validRemoteIP(v string) bool {
	if v == "" {
		return false
	}
	if _, _, err := net.ParseCIDR(v); err == nil {
		return true
	}
	return net.ParseIP(v) != nil
}

func removeVncFirewallRule() {
	runHidden(`C:\Windows\System32\netsh.exe`, "advfirewall", "firewall", "delete", "rule",
		"name="+firewallRuleName)
}

// ── cleanup ──────────────────────────────────────────────────────────────────────

// cleanup tears down what THIS run set up, respecting pre-existing installs. Idempotent.
func cleanup(s *appState) {
	s.mu.Lock()
	if s.cleanedUp {
		s.mu.Unlock()
		return
	}
	s.cleaning = true
	s.mu.Unlock()

	// Wait for a half-finished setup rather than tearing down underneath it: closing the
	// window during the UltraVNC install used to run both at once.
	//
	// ⚠️ This budget must exceed what runFlow can legitimately take, which is both install
	// timeouts back to back (5 min each) plus the waits between them. At three minutes the
	// wait expired while the install was still going, teardown ran to completion, the process
	// exited — and the install then finished behind it, writing our session password into the
	// ini and starting the VNC service, with the state file already deleted so the next
	// launch would not repair it. That is the outcome this whole audit exists to prevent,
	// reached without an attacker.
	flowFinished := waitFor(&s.flow, 12*time.Minute)

	apiEnd(s.server, s.code) // tell the server to drop the peer immediately

	s.mu.Lock()
	vncTouched, wgTouched := s.vncTouched, s.wgTouched
	s.mu.Unlock()

	if vncTouched {
		removeUltraVnc(s)
	}
	removeVncFirewallRule()

	if wgTouched {
		removeTunnel()
	}

	// Last, so that a crash anywhere above leaves the marker behind and the next launch
	// finishes the job. If setup was still running when we gave up waiting for it, the
	// marker STAYS: we cannot say this machine is clean, and the next launch must be able
	// to finish what we could not.
	if flowFinished {
		os.Remove(fwSnapshotPath)
		os.Remove(statePath)
		os.Remove(legacyStatePath)
	}

	s.mu.Lock()
	s.cleanedUp = true
	s.cleaning = false
	s.mu.Unlock()
}

// removeTunnel drops the tunnel service AND the config it left behind. WireGuard keeps its
// own encrypted copy under Data\Configurations; /uninstalltunnelservice does not remove it,
// so every session used to add another permanent "plsupport" entry to the customer's
// WireGuard UI. Our Windows uninstall script has always deleted these explicitly.
func removeTunnel() {
	runHidden(wireguardPath, "/uninstalltunnelservice", tunnelName)
	time.Sleep(1 * time.Second)
	os.Remove(confPath)
	os.Remove(legacyConfPath)
	for _, p := range wgLeftovers {
		os.Remove(p)
	}
}

// ── recovery ─────────────────────────────────────────────────────────────────────

// writeState records, before we touch anything, what this machine looked like. A few bytes,
// but it is the difference between a recovery that puts the customer's own VNC server back
// and one that deletes it.
func writeState(s *appState) {
	b, err := json.Marshal(s.snapshot())
	if err != nil {
		return
	}
	if err := os.WriteFile(statePath, b, 0600); err == nil {
		lockDownPath(statePath, false)
	}
}

// readState loads the marker left by an interrupted session. Builds up to v4 wrote a single
// "0"/"1" byte to C:\Windows\Temp; that file is still read here so this build can finish
// cleaning up after one of them.
func readState() (ps persistedState, found, legacy bool) {
	if raw, err := os.ReadFile(statePath); err == nil {
		if json.Unmarshal(raw, &ps) == nil {
			ps.UvncDir = boundedUvncDir(ps.UvncDir)
			return ps, true, false
		}
	}
	if raw, err := os.ReadFile(legacyStatePath); err == nil {
		return persistedState{VncWasInstalled: strings.TrimSpace(string(raw)) == "1"}, true, true
	}
	return persistedState{}, false, false
}

// boundedUvncDir refuses any install folder that is not one of the two we ever install
// into. The recorded path ends up in a recursive force-delete, so it must never be
// something a state file can choose freely.
func boundedUvncDir(dir string) string {
	for _, d := range uvncDirs {
		if strings.EqualFold(strings.TrimRight(dir, `\`), d) {
			return d
		}
	}
	return ""
}

// recoverPreviousSession undoes a session that never cleaned up after itself.
//
// ⚠️ Cleanup only ran when the window was closed. End Task, a crash, a power cut or a
// client simply shutting the lid and rebooting left the machine with OUR session password
// in their ultravnc.ini, our WireGuard tunnel service installed, and — before the fix
// above — their own VNC firewall rules deleted. Nothing ever put any of it back, and the
// client had no way to know. The .plbak files and this marker are the evidence needed to
// finish the job on the next launch, so the tool repairs itself instead of leaving damage
// behind on a stranger's PC.
//
// Best-effort and silent: if there is nothing to recover it does nothing at all.
func recoverPreviousSession() {
	ps, ok, legacy := readState()
	if !ok {
		return // no interrupted session
	}

	// If the dead session installed UltraVNC itself, our downloaded installer is still
	// sitting in our working folder — cleanup deletes it, so its presence is proof. Without
	// that proof we do not run an uninstaller: between the two launches the client may have
	// installed UltraVNC themselves, and removing software we cannot show we put there is the
	// exact mistake this whole change is about.
	preexisting := ps.VncWasInstalled
	if !preexisting && !fileExists(vncSetupPath) {
		preexisting = true
	}

	// ⚠️ A LEGACY MARKER NEVER AUTHORISES AN UNINSTALL.
	//
	// Builds up to v4 kept both the marker and the downloaded installer in C:\Windows\Temp,
	// where any signed-in user can create files. Two empty files planted there — a
	// plsupport.state containing "0" and a plsupport-uvnc.exe — are enough to make the next
	// elevated launch believe it installed the customer's own UltraVNC, and silently run
	// their uninstaller and force-delete the folder. The evidence is forgeable, so it does
	// not get a vote: a legacy marker means "undo OUR changes", never "remove software".
	// This is the rule we apply whenever ownership is unknown: it restrains what we DELETE
	// and never what we maintain. The cost is an idle UltraVNC left installed after a v4 crash;
	// the alternative cost is deleting a stranger's software on a forged file.
	if legacy {
		preexisting = true
	}
	if ps.UvncDir == "" {
		ps.UvncDir = uvncDir()
	}
	if ps.UvncService == "" {
		ps.UvncService = uvncServiceName(ps.UvncDir)
	}

	prev := &appState{
		server:          defaultServer,
		probed:          true,
		vncWasInstalled: preexisting,
		uvncDir:         ps.UvncDir,
		uvncService:     ps.UvncService,
		vncTouched:      true,
		wgTouched:       true,
	}
	// Deliberately reuses the normal teardown: one definition of "undo", so a fix to the
	// live path can never drift away from the recovery path.
	removeUltraVnc(prev)
	removeVncFirewallRule()
	removeTunnel()
	os.Remove(statePath)
	os.Remove(legacyStatePath)
}

// forceCleanup is the manual recovery path (-cleanup CODE): it cuts remote access by stopping
// VNC and removing the tunnel + firewall rule. It does not uninstall UltraVNC, which may be the
// customer's own. The tool installs no scheduled task or other persistence — nothing is left
// running or auto-starting on the machine after a session.
func forceCleanup(server, code string) {
	apiEnd(server, code)
	removeVncFirewallRule()
	dir := uvncDir()
	stopUvnc(dir, uvncServiceName(dir))
	// Give the customer their own config back if we have a copy of it. A file with no
	// backup is deliberately left alone: this path can be run on a machine we never touched,
	// and deleting an ini we cannot prove is ours is the one thing we never do. Our password
	// stays behind in that case, on a stopped service, in an admin-only file — the session
	// itself is already dead because the tunnel and the rule are gone.
	for _, p := range iniPaths(dir) {
		if fileExists(p + ".plbak") {
			os.Remove(p)
			copyFile(p+".plbak", p)
			os.Remove(p + ".plbak")
		}
	}
	removeTunnel()
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
	tmp := filepath.Join(workDir, "wireguard-installer.exe")
	if err := download(wireguardInstaller, tmp); err != nil {
		return err
	}
	// About to run as Administrator. We cannot pin a hash for someone else's installer —
	// they publish new versions — so we require a valid Authenticode signature instead.
	if err := verifyAuthenticode(tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	if _, err := runHiddenFor(5*time.Minute, tmp, "/S"); err != nil {
		return err
	}
	for i := 0; i < 30; i++ {
		if fileExists(wireguardPath) {
			os.Remove(tmp)
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	os.Remove(tmp)
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

	// The server's own clock, read from the response's Date header, so the expiry above can
	// be turned into a duration without trusting this machine's time. See sessionLifeFrom.
	serverNow time.Time
}

// whoResponse is who the server says is asking to connect.
type whoResponse struct {
	Technician string `json:"technician"`
	Company    string `json:"company"`
}

// apiWho asks the server who created this session, BEFORE anything on this machine is
// touched. The answer comes from ProxyLink's own records — a caller cannot supply it —
// which is the one thing a scammer running our script cannot forge.
func apiWho(server, code string) (*whoResponse, error) {
	resp, err := apiClient.Get(fmt.Sprintf("%s/api/support/%s/who", server, url.PathEscape(code)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 404:
		return nil, fmt.Errorf("code not found or expired")
	case 429:
		return nil, fmt.Errorf("too many attempts, wait a moment")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("server error %d", resp.StatusCode)
	}
	var w whoResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&w); err != nil {
		return nil, fmt.Errorf("invalid server response")
	}
	return &w, nil
}

func apiRegister(server, code, pubKey string) (*registerResponse, error) {
	body, _ := json.Marshal(map[string]string{"public_key": pubKey})
	resp, err := apiClient.Post(fmt.Sprintf("%s/api/support/%s/register", server, url.PathEscape(code)), "application/json", bytes.NewReader(body))
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
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("server error %d: %s", resp.StatusCode, string(b))
	}
	var r registerResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return nil, fmt.Errorf("invalid server response")
	}
	if d, err := http.ParseTime(resp.Header.Get("Date")); err == nil {
		r.serverNow = d
	}
	return &r, nil
}

func apiReady(server, code string) error {
	resp, err := apiClient.Post(fmt.Sprintf("%s/api/support/%s/ready", server, url.PathEscape(code)), "application/json", bytes.NewReader([]byte("{}")))
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
	resp, e := apiClient.Get(fmt.Sprintf("%s/api/support/%s/status", server, url.PathEscape(code)))
	if e != nil {
		return "", "", e
	}
	defer resp.Body.Close()
	var r struct {
		Status string `json:"status"`
		Viewer string `json:"viewer"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r)
	return r.Status, r.Viewer, nil
}

func apiEnd(server, code string) {
	if code == "" {
		return
	}
	resp, err := apiClient.Post(fmt.Sprintf("%s/api/support/%s/end", server, url.PathEscape(code)), "application/json", bytes.NewReader([]byte("{}")))
	if err == nil {
		resp.Body.Close()
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────────

// prepareWorkDir creates our private working folder and strips it back to Administrators
// and SYSTEM. Go's file modes do not map to Windows ACLs, so 0600 on a file under
// C:\Windows\Temp bought nothing: any signed-in user could read the WireGuard private key,
// or pre-create the installer path for us to truncate and then execute as Administrator.
// ⚠️ AN ACL IS NOT ENOUGH — THE OWNER HAS TO BE TAKEN TOO.
//
// C:\ProgramData lets ordinary users create subfolders, and whoever creates one OWNS it. A
// Windows object's owner keeps an implicit WRITE_DAC no matter what the DACL says, so a
// standard user who pre-creates C:\ProgramData\ProxyLinkSupport before a session can hand
// themselves back full control the instant after our icacls runs, and then swap the
// hash-verified installer for their own in the gap between the check and the exec — which we
// perform as Administrator. Moving off C:\Windows\Temp only closed the file version of that
// hole; pre-creating the DIRECTORY walked straight back in. So: refuse a reparse point, take
// ownership, and only then set the DACL.
func prepareWorkDir() error {
	// A junction planted at this path would silently relocate everything we write, including
	// the installer we are about to run. Remove the link itself (never its target) and start
	// again with a real directory.
	if fi, err := os.Lstat(workDir); err == nil && fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		os.Remove(workDir)
	}
	if err := os.MkdirAll(workDir, 0700); err != nil {
		return err
	}
	takeOwnership(workDir)
	lockDownPath(workDir, true)
	return nil
}

// takeOwnership makes Administrators the owner of path and everything under it, so no
// earlier owner keeps the implicit right to rewrite its permissions.
func takeOwnership(path string) {
	runHidden(`C:\Windows\System32\icacls.exe`, path, "/setowner", "*S-1-5-32-544", "/T", "/C", "/Q")
}

func lockDownPath(path string, container bool) {
	grant := ":(F)"
	if container {
		grant = ":(OI)(CI)(F)"
	}
	// Well-known SIDs, so this is right on a Greek or German Windows too:
	// S-1-5-32-544 = Administrators, S-1-5-18 = SYSTEM.
	runHidden(`C:\Windows\System32\icacls.exe`, path, "/inheritance:r",
		"/grant", "*S-1-5-32-544"+grant, "/grant", "*S-1-5-18"+grant)
}

func download(url, dest string) error {
	resp, err := downloadClient.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download status %d", resp.StatusCode)
	}
	// O_EXCL after an explicit remove: we never write through a file, symlink or junction
	// somebody else left at this path and then run it as Administrator.
	os.Remove(dest)
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, cErr := io.Copy(f, resp.Body)
	f.Close()
	if cErr != nil {
		os.Remove(dest)
		return cErr
	}
	lockDownPath(dest, false)
	return nil
}

// verifySHA256 checks a file we are about to execute against a hash compiled into this
// signed binary.
func verifySHA256(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, want) {
		return fmt.Errorf("installer did not match the expected file")
	}
	return nil
}

// verifyAuthenticode requires Windows itself to consider the file's signature valid.
func verifyAuthenticode(path string) error {
	out, err := runPowerShell(fmt.Sprintf(
		`(Get-AuthenticodeSignature -LiteralPath '%s').Status`, psEscape(path)))
	if err != nil || strings.TrimSpace(out) != "Valid" {
		return fmt.Errorf("installer signature could not be verified")
	}
	return nil
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return writeFileExclusive(dst, b)
}

// writeFileExclusive removes any existing path and creates the file fresh, so a plain
// truncating write can never follow a link or reuse a handle somebody else established.
func writeFileExclusive(path string, data []byte) error {
	os.Remove(path)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, wErr := f.Write(data)
	cErr := f.Close()
	if wErr != nil {
		return wErr
	}
	return cErr
}

// psEscape makes a value safe to embed inside a PowerShell single-quoted string.
func psEscape(v string) string {
	return strings.ReplaceAll(v, "'", "''")
}

// waitFor blocks on wg, but never longer than d: a stuck installer must not leave the
// customer staring at "cleaning up" forever. Reports whether the wait actually completed —
// a timeout means work is still running and cleanup cannot claim the machine is clean.
func waitFor(wg *sync.WaitGroup, d time.Duration) bool {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

func runHidden(name string, args ...string) (string, error) {
	return runHiddenFor(2*time.Minute, name, args...)
}

// runHiddenFor runs a command with a hard time limit. Every external command here can hang
// — a wedged installer, a service that never answers — and without a limit the hang becomes
// the UI's, with both controls disabled and End Task the only way out.
func runHiddenFor(d time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func runPowerShell(script string) (string, error) {
	return runPowerShellFor(2*time.Minute, script)
}

func runPowerShellFor(d time.Duration, script string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell", "-NonInteractive", "-NoProfile", "-Command", script)
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
