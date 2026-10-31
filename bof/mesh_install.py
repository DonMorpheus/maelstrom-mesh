# compat: mop/GUI may load this name
import os
_p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mesh.py")
exec(compile(open(_p, encoding="utf-8").read(), _p, "exec"), globals())
