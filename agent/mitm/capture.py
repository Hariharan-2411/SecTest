# mitmproxy addon: append each flow as JSONL (bounded + header-only secrets) to iris_out.
import json
from mitmproxy import ctx

def load(loader):
    loader.add_option("iris_out", str, "", "capture output file")

def response(flow):
    try:
        out = ctx.options.iris_out
        if not out:
            return
        rec = {
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "status": flow.response.status_code,
            "req_headers": dict(flow.request.headers),
            "req_body": flow.request.get_text(strict=False)[:1000],
            "res_headers": dict(flow.response.headers),
            "res_body": flow.response.get_text(strict=False)[:1000],
        }
        with open(out, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        pass
