"""Clean fixture model.

Every suspicious-looking token below is inside a comment or string and must
never produce a finding; model.eval() must be recognized as a method call.
"""
import torch


class FixtureModel(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.config = {"note": "eval( appears in strings only"}

    def evaluate_in_eval_mode(self):
        # eval("os.system('id')") in a comment must never fire
        self.eval()
        return self.config
