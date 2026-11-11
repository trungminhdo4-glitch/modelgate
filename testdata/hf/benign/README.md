---
library_name: fixture
tags:
  - fixture
---

# fixture/benign

Known-harmless fixture repository used by ModelGate's acceptance tests.

```python
from transformers import AutoModel
model = AutoModel.from_pretrained("fixture/benign")
```

The example above does not use trust_remote_code.
