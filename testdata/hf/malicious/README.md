---
library_name: fixture
---

# fixture/malicious

Synthetic hostile fixture repository for ModelGate tests.

```python
from transformers import AutoModel
model = AutoModel.from_pretrained("fixture/malicious", trust_remote_code=True)
```
