//go:build linux

package control

import (
	"bytes"
	"context"
	"github.com/petauron/glivela/ipquality"
	"io"
	"net"
	"os/exec"
	"time"
)

const qualityImage = "xykt/ipquality@sha256:26258a197cc03c186d41c26bd871d36ccc6ee269baf97762cfdd2b7d694c8dda"
const qualityScript = `set -eu
curl --proto '=https' --tlsv1.2 -fsSL --max-time 30 https://raw.githubusercontent.com/xykt/IPQuality/ad222ab16778be2a13a174cd1acbd69fb4cac6b7/ip.sh -o /tmp/upstream.sh
echo 'ffb17dae790341c13023a94c5141775974dd73a3653ca5fba5c4648fc5588402  /tmp/upstream.sh' | sha256sum -c - >/dev/null
# DB-IP queries /self. Keep the selected source address for both families;
# upstream otherwise clears its binding for IPv6 and can report the IPv4 exit.
sed -e '/^check_mail$/d' -e '/^\[\[ \$2 -eq 4 \]\]&&check_dnsbl /d' -e '/^show_mail \$2$/d' -e '/^countRunTimes$/d' -e '/^show_ad$/d' -e 's/\$tmpcurlarg/\$CurlARG/g' -e 's/\${rawgithub}main\//\${rawgithub}ad222ab16778be2a13a174cd1acbd69fb4cac6b7\//g' /tmp/upstream.sh > /tmp/check.sh
bash /tmp/check.sh -i "$1" "$2" -E -n -p -f -j > /tmp/report.json || [ "$?" -eq 1 ]
cat /tmp/report.json
if [ "$2" = '-4' ] && curl --proto '=https' --tlsv1.2 --ipv4 --interface "$1" --noproxy '*' --max-time 12 --max-filesize 16384 -fsS https://my.ippure.com/v1/info -o /tmp/ippure.json 2>/dev/null; then
  printf '\n__MERIDIAN_IPPURE__\n'
  cat /tmp/ippure.json
fi
`

type qualityOutput struct {
	bytes.Buffer
	exceeded bool
}

func (b *qualityOutput) Write(v []byte) (int, error) {
	n := len(v)
	remaining := 128*1024 - b.Len()
	if n > remaining {
		b.exceeded = true
		v = v[:max(0, remaining)]
	}
	_, _ = b.Buffer.Write(v)
	return n, nil
}
func executeQuality(parent context.Context, a QualityAssignment) (result ipquality.Result) {
	result.Error = "detection_failed"
	ctx, cancel := context.WithDeadline(parent, minTime(a.ExpiresAt, time.Now().Add(4*time.Minute)))
	defer cancel()
	// Reuse the approved detector at its immutable digest. Docker runs never
	// resolve a mutable tag, and downloads share the job deadline.
	inspect := exec.CommandContext(ctx, "docker", "image", "inspect", qualityImage)
	inspect.Stdout = io.Discard
	inspect.Stderr = io.Discard
	if inspect.Run() != nil {
		pull := exec.CommandContext(ctx, "docker", "pull", qualityImage)
		pull.Stdout = io.Discard
		pull.Stderr = io.Discard
		if pull.Run() != nil {
			if ctx.Err() != nil {
				return ipquality.Result{Error: "timeout"}
			}
			return ipquality.Result{Error: "download_failed"}
		}
	}
	family, bind := "-4", "0.0.0.0"
	if net.ParseIP(a.Address).To4() == nil {
		family, bind = "-6", "::"
	}
	if addresses, err := net.InterfaceAddrs(); err == nil {
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil && ip.Equal(net.ParseIP(a.Address)) {
				bind = ip.String()
				break
			}
		}
	}
	name := "glivela-quality-" + a.ID
	defer func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(parent), 15*time.Second)
		defer done()
		cmd := exec.CommandContext(cleanup, "docker", "rm", "-f", name)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if cmd.Run() != nil {
			result = ipquality.Result{Error: "detection_failed"}
		}
	}()
	cmd := exec.CommandContext(ctx, "docker", "run", "--pull=never", "--name", name, "--network=host", "--user", "65534:65534", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=128m", "--memory-swap=128m", "--cpus=0.5", "--pids-limit=96", "--log-driver=none", "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m,mode=1777", "--workdir=/tmp", "--env", "HOME=/tmp", "--env", "TERM=dumb", "--label", "io.glivela.diagnostic=ip-quality", "--entrypoint", "timeout", qualityImage, "-s", "KILL", "210", "/bin/sh", "-c", qualityScript, "ip-quality", bind, family)
	var output qualityOutput
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	err := cmd.Run()
	if ctx.Err() != nil {
		return ipquality.Result{Error: "timeout"}
	}
	if err != nil {
		return result
	}
	if output.exceeded {
		return ipquality.Result{Error: "invalid_report"}
	}
	parts := bytes.SplitN(output.Bytes(), []byte("\n__MERIDIAN_IPPURE__\n"), 2)
	report, err := ipquality.Parse(parts[0], a.Address)
	if err != nil {
		return ipquality.Result{Error: "invalid_report"}
	}
	pure := missingIPPure(a.Address, time.Now())
	if len(parts) == 2 {
		pure = parseIPPure(parts[1], a.Address, time.Now())
	}
	report.IPPure = &pure
	return ipquality.Result{Report: &report}
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
