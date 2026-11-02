"""Apply two narrow, checked hooks to the pinned upstream, or fail the build."""
import ast
from pathlib import Path

p = Path("/opt/mtprotoproxy/mtprotoproxy.py")
source = p.read_text()
tree = ast.parse(source)
init = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "init_config")
lines = source.splitlines(keepends=True)
lines.insert(init.end_lineno, '    revocation.reconcile(config.USERS, sys.argv[1])\n')
source = "import revocation\n" + "".join(lines)
needle = "        return reader, writer, proto_tag, user, dc_idx, enc_key + enc_iv, peer"
assert source.count(needle) == 1, "Pinned upstream handshake changed"
source = source.replace(needle, "        revocation.register(writer.transport, user, secret.hex(), config.USERS)\n" + needle)
ast.parse(source)
p.write_text(source)
