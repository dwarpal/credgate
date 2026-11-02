"""Screenshots of the policy editor for the docs, through headless Chrome.

Uses the Chrome DevTools protocol with the standard library only. Start the
editor on a fresh copy of the example policy first, on port 8611:

    cp examples/policies/bank-default.yaml /tmp/editor/bank.yaml
    Rscript -e 'shiny::runApp(credgate::policy_editor("/tmp/editor/bank.yaml",
                user = "infosec-demo"), port = 8611)'
    python3 tools/policy-editor-screenshots.py docs/images/policy-editor /tmp/chrome-profile

The screenshots save a change to that copy (to fill the Changes tab) and show
the policy file as /srv/credgate/bank-default.yaml.
"""
import base64, json, os, socket, struct, subprocess, sys, time, urllib.request

APP = "http://127.0.0.1:8611/"
OUT = sys.argv[1]
PROFILE = sys.argv[2]
CHROME = os.environ.get("CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
PORT = 9333

try:
    urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json/version", timeout=1)
    running = True
except Exception:
    running = False
chrome = None if running else subprocess.Popen([CHROME, "--headless=new", f"--remote-debugging-port={PORT}",
                           f"--user-data-dir={PROFILE}", "--hide-scrollbars", "--no-first-run",
                           "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class WS:
    def __init__(self, url):
        host, path = url[len("ws://"):].split("/", 1)
        h, p = host.split(":")
        self.s = socket.create_connection((h, int(p)))
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall((f"GET /{path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
                        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                        "Sec-WebSocket-Version: 13\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += self.s.recv(4096)
        self.n = 0

    def _recv(self, n):
        b = b""
        while len(b) < n:
            chunk = self.s.recv(n - len(b))
            if not chunk:
                raise ConnectionError
            b += chunk
        return b

    def send(self, obj):
        data = json.dumps(obj).encode()
        head = bytes([0x81])
        n = len(data)
        if n < 126:
            head += bytes([0x80 | n])
        elif n < 65536:
            head += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            head += bytes([0x80 | 127]) + struct.pack(">Q", n)
        mask = os.urandom(4)
        self.s.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def recv(self):
        msg = b""
        while True:
            b0, b1 = self._recv(2)
            n = b1 & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._recv(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._recv(8))[0]
            msg += self._recv(n)
            if b0 & 0x80:
                return json.loads(msg)

    def call(self, method, **params):
        self.n += 1
        self.send({"id": self.n, "method": method, "params": params})
        while True:
            r = self.recv()
            if r.get("id") == self.n:
                if "error" in r:
                    raise RuntimeError(r["error"])
                return r.get("result", {})


for _ in range(200):
    try:
        tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json"))
        break
    except Exception:
        time.sleep(0.2)
page = next(t for t in tabs if t["type"] == "page")
ws = WS(page["webSocketDebuggerUrl"])


def js(code):
    r = ws.call("Runtime.evaluate", expression=code, awaitPromise=True, returnByValue=True)
    return r.get("result", {}).get("value")


def shot(name, w=1280, h=860, dark=False, full=False):
    ws.call("Emulation.setEmulatedMedia", features=[{"name": "prefers-color-scheme", "value": "dark" if dark else "light"}])
    js(f"document.documentElement.setAttribute('data-bs-theme', '{'dark' if dark else 'light'}')")
    js("document.querySelector('.cg-file').innerText = '/srv/credgate/bank-default.yaml'")
    time.sleep(0.8)
    if full:
        h = int(js("Math.ceil(document.documentElement.scrollHeight)"))
        ws.call("Emulation.setDeviceMetricsOverride", width=w, height=h, deviceScaleFactor=2, mobile=False)
        time.sleep(0.6)
    r = ws.call("Page.captureScreenshot", format="png")
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(base64.b64decode(r["data"]))
    ws.call("Emulation.setDeviceMetricsOverride", width=w, height=860, deviceScaleFactor=2, mobile=False)
    print("wrote", name)


def tab(label):
    js(f"[...document.querySelectorAll('.nav-link')].find(a => a.innerText.trim() === '{label}').click()")
    time.sleep(1.2)


try:
    ws.call("Page.enable")
    ws.call("Emulation.setDeviceMetricsOverride", width=1280, height=860, deviceScaleFactor=2, mobile=False)
    ws.call("Page.navigate", url=APP)
    time.sleep(4)

    shot("endpoints.png")
    shot("endpoints-dark.png", dark=True)

    tab("Rules")
    js("document.querySelector('[data-pick=\"cvv-never-leaves\"]').click()")
    time.sleep(1)
    js("window.scrollTo(0, 0)")
    shot("rules.png")

    tab("Try it")
    js("document.getElementById('try_endpoint').selectize.setValue('claude')")
    time.sleep(1.5)
    shot("try-blocked.png", dark=True)
    js("""(() => { const e = document.getElementById('try_text');
          e.value = 'Customer PAN ABCPE1234F, mobile +91 98765 43210, asked about a loan.';
          $(e).trigger('change'); })()""")
    time.sleep(1.5)
    shot("try-redacted.png")

    # a change, saved with a note, to fill the Changes tab
    tab("Endpoints")
    js("""(async () => {
      const w = ms => new Promise(r => setTimeout(r, ms));
      const set = (id, v) => { const e = document.getElementById(id); e.value = v; $(e).trigger('change'); };
      set('ep_name', 'vllm-risk'); document.getElementById('ep_tier').selectize.setValue('internal');
      set('ep_provider', 'vllm'); set('ep_url', 'https://risk-llm.bank.internal/v1');
      set('ep_description', 'Risk team GPU server'); await w(600);
      document.getElementById('ep_apply').click(); await w(1000);
      set('note', 'CHG-1042: risk team GPU server approved'); await w(400);
      document.getElementById('save').click(); await w(1200);
      document.getElementById('default_action').selectize.setValue('block'); await w(800);
    })()""")
    tab("Changes")
    shot("changes.png", full=True)
finally:
    if chrome:
        chrome.terminate()
