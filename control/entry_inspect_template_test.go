package control

import (
	"bytes"
	"encoding/json"
	"testing"
	"text/template"
)

func TestEntryInspectOptionalDockerHostFields(t *testing.T) {
	_, _, state := entryContainerFixture(t, false)
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document["Id"] = document["ID"]
	host := document["Host"].(map[string]any)
	host["RestartPolicy"] = map[string]any{"Name": host["Restart"]}
	document["HostConfig"] = host
	document["NetworkSettings"] = map[string]any{"Networks": document["Networks"]}
	document["State"].(map[string]any)["Pid"] = float64(0)
	tmpl := template.Must(template.New("inspect").Option("missingkey=error").Funcs(template.FuncMap{
		"json": func(value any) (string, error) { encoded, err := json.Marshal(value); return string(encoded), err },
	}).Parse(entryInspectTemplate))
	for _, present := range []bool{false, true} {
		if present {
			host["Sysctls"] = map[string]any{"net.ipv4.ip_forward": "1"}
			host["Tmpfs"] = map[string]any{"/tmp": "rw,noexec"}
		} else {
			delete(host, "Sysctls")
			delete(host, "Tmpfs")
		}
		var output bytes.Buffer
		if err := tmpl.Execute(&output, document); err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeEntryContainer(output.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if present {
			if string(decoded.Host.Sysctls["net.ipv4.ip_forward"]) != `"1"` || string(decoded.Host.Tmpfs["/tmp"]) != `"rw,noexec"` {
				t.Fatal("explicit host settings lost")
			}
		} else if len(decoded.Host.Sysctls) != 0 || len(decoded.Host.Tmpfs) != 0 {
			t.Fatal("absent settings changed")
		}
	}
}
