data = open("main", "rb").read()
data = data.replace(b"run.zig", b"././run")
open("main", "wb").write(data)