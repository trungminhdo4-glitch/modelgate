package scan

import (
	"strings"
	"testing"
)

func TestDeserLoadersDetected(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, code, rule string
	}{
		{"pickle_load", "import pickle\nobj = pickle.load(handle)\n", "MG-DESER-001"},
		{"pickle_loads", "import pickle\nobj = pickle.loads(blob)\n", "MG-DESER-001"},
		{"cpickle_load", "import cPickle\nobj = cPickle.load(handle)\n", "MG-DESER-001"},
		{"underscore_pickle", "import _pickle\nobj = _pickle.loads(blob)\n", "MG-DESER-001"},
		{"pickle_unpickler", "import pickle\nobj = pickle.Unpickler(handle).load()\n", "MG-DESER-001"},
		{"marshal_load_file", "import marshal\nobj = marshal.load(handle)\n", "MG-DESER-001"},
		{"marshal_loads", "import marshal\nobj = marshal.loads(blob)\n", "MG-DESER-001"},
		{"joblib_load", "import joblib\nobj = joblib.load('model.joblib')\n", "MG-DESER-001"},
		{"joblib_alias", "import joblib as jl\nobj = jl.load('model.joblib')\n", "MG-DESER-001"},
		{"joblib_alias_in_list", "import os, joblib as jl\nobj = jl.load(path)\n", "MG-DESER-001"},
		{"dill_load", "import dill\nobj = dill.load(handle)\n", "MG-DESER-001"},
		{"dill_loads", "import dill\nobj = dill.loads(blob)\n", "MG-DESER-001"},
		{"from_dill_import_load", "from dill import load\nobj = load(handle)\n", "MG-DESER-001"},
		{"from_pickle_import_as", "from pickle import loads as unpack\nobj = unpack(blob)\n", "MG-DESER-001"},
		{"from_pickle_paren_list", "from pickle import (\n    dumps,\n    loads,\n)\nobj = loads(blob)\n", "MG-DESER-001"},
		{"from_pickle_star", "from pickle import *\nobj = loads(blob)\n", "MG-DESER-001"},
		{"pickle_alias", "import pickle as pk\nobj = pk.loads(blob)\n", "MG-DESER-001"},
		{"cloudpickle_load", "import cloudpickle\nfn = cloudpickle.load(handle)\n", "MG-DESER-001"},
		{"cloudpickle_loads", "import cloudpickle\nfn = cloudpickle.loads(blob)\n", "MG-DESER-001"},
		{"jsonpickle_decode", "import jsonpickle\nobj = jsonpickle.decode(text)\n", "MG-DESER-001"},
		{"shelve_open", "import shelve\ndb = shelve.open('cache')\n", "MG-DESER-001"},
		{"pandas_read_pickle", "import pandas\ndf = pandas.read_pickle('df.pkl')\n", "MG-DESER-001"},
		{"pd_read_pickle", "import pandas as pd\ndf = pd.read_pickle('df.pkl')\n", "MG-DESER-001"},
		{"from_pandas_read_pickle", "from pandas import read_pickle\ndf = read_pickle(path)\n", "MG-DESER-001"},
		{"numpy_allow_pickle", "import numpy as np\narr = np.load('a.npy', allow_pickle=True)\n", "MG-DESER-001"},
		{"numpy_allow_pickle_nested", "import numpy\narr = numpy.load(open(p, 'rb'), allow_pickle = True)\n", "MG-DESER-001"},
		{"numpy_alias_allow_pickle", "import numpy as npy\narr = npy.load(p, allow_pickle=True)\n", "MG-DESER-001"},
		{"yaml_load_default", "import yaml\ncfg = yaml.load(handle)\n", "MG-DESER-001"},
		{"yaml_load_full_loader", "import yaml\ncfg = yaml.load(handle, Loader=yaml.FullLoader)\n", "MG-DESER-001"},
		{"yaml_load_unsafe_loader", "import yaml\ncfg = yaml.load(handle, Loader=yaml.UnsafeLoader)\n", "MG-DESER-001"},
		{"yaml_unsafe_load", "import yaml\ncfg = yaml.unsafe_load(handle)\n", "MG-DESER-001"},
		{"yaml_load_all", "import yaml\ndocs = yaml.load_all(handle, Loader=yaml.Loader)\n", "MG-DESER-001"},
		{"semicolon_import", "import os; import dill as d\nobj = d.loads(blob)\n", "MG-DESER-001"},
		{"torch_load_plain", "import torch\nstate = torch.load('w.bin')\n", "MG-DESER-002"},
		{"torch_weights_only_false", "import torch\nstate = torch.load('w.bin', weights_only=False)\n", "MG-DESER-002"},
		{"torch_from_import", "from torch import load\nstate = load('w.bin')\n", "MG-DESER-002"},
		{"torch_alias", "import torch as T\nstate = T.load('w.bin', map_location='cpu')\n", "MG-DESER-002"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fs := AnalyzePython("fixture.py", []byte(tc.code))
			if !hasRule(fs, tc.rule) {
				t.Fatalf("expected %s for %q, got %+v", tc.rule, tc.code, fs)
			}
		})
	}
}

func TestDeserLoadersIgnoreSafeCalls(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, code string }{
		{"json_load", "import json\ncfg = json.load(handle)\n"},
		{"json_loads", "import json\ncfg = json.loads(text)\n"},
		{"yaml_safe_load", "import yaml\ncfg = yaml.safe_load(handle)\n"},
		{"yaml_safe_load_all", "import yaml\ndocs = yaml.safe_load_all(handle)\n"},
		{"yaml_load_safe_loader", "import yaml\ncfg = yaml.load(handle, Loader=yaml.SafeLoader)\n"},
		{"yaml_load_csafe_loader", "import yaml\ncfg = yaml.load(handle, Loader=yaml.CSafeLoader)\n"},
		{"yaml_load_positional_safe", "from yaml import load, SafeLoader\ncfg = load(handle, SafeLoader)\n"},
		{"torch_weights_only", "import torch\nstate = torch.load('w.bin', weights_only=True)\n"},
		{"torch_weights_only_multiline", "import torch\nstate = torch.load(\n    path,\n    map_location=dev(),\n    weights_only=True,\n)\n"},
		{"numpy_load_plain", "import numpy as np\narr = np.load('a.npy')\n"},
		{"numpy_allow_pickle_false", "import numpy as np\narr = np.load('a.npy', allow_pickle=False)\n"},
		{"pickle_dumps", "import pickle\nblob = pickle.dumps(obj)\n"},
		{"method_load", "state = self.load(path)\nother = model.loads(x)\n"},
		{"attribute_named_pickle", "obj = self.pickle.loads(blob)\n"},
		{"def_load", "from pickle import load\n\ndef load(path):\n    return path\n"},
		{"from_pickle_only_dumps", "from pickle import dumps\nblob = dumps(obj)\nload(path)\n"},
		{"alias_without_call", "import joblib as jl\njl.dump(obj, path)\n"},
		{"safetensors", "from safetensors.torch import load_file\nstate = load_file('w.safetensors')\n"},
		{"in_comment", "# pickle.loads(blob) and yaml.load(f)\n"},
		{"in_string", "doc = 'call dill.load(f) or torch.load(p) here'\n"},
		{"shelve_word", "shelved = open('x')\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fs := AnalyzePython("fixture.py", []byte(tc.code))
			if hasRule(fs, "MG-DESER-001") || hasRule(fs, "MG-DESER-002") {
				t.Fatalf("safe code %q wrongly flagged: %+v", tc.code, fs)
			}
		})
	}
}

func TestCallArgs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		src  string
		open int
		want string
	}{
		{"f(a, g(b), c) + 1", 1, "a, g(b), c"},
		{"f(unclosed", 1, "unclosed"},
		{"f()", 1, ""},
		{"x", 0, ""},
		{"f(", 5, ""},
	}
	for _, tc := range cases {
		if got := callArgs([]byte(tc.src), tc.open); got != tc.want {
			t.Fatalf("callArgs(%q, %d) = %q, want %q", tc.src, tc.open, got, tc.want)
		}
	}
}

func TestDeserLoaderLineIsFirstCall(t *testing.T) {
	t.Parallel()
	src := "import pickle\nimport joblib as jl\n\nobj = jl.load(p)\nother = pickle.loads(b)\n"
	f := ruleFor(AnalyzePython("x.py", []byte(src)), "MG-DESER-001")
	if f.Line != 4 {
		t.Fatalf("line = %d, want 4", f.Line)
	}
	if want := "2 occurrence(s)"; !strings.Contains(f.Message, want) {
		t.Fatalf("message = %q, want %q", f.Message, want)
	}
}
