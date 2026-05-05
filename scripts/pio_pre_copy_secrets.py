"""If include/secrets.h is missing, copy from secrets.example.h so `pio run` works on a fresh clone."""
import os
import shutil

Import("env")

project_dir = env.subst("$PROJECT_DIR")
dest = os.path.join(project_dir, "include", "secrets.h")
src = os.path.join(project_dir, "include", "secrets.example.h")
if not os.path.isfile(dest) and os.path.isfile(src):
    shutil.copyfile(src, dest)
    print("Copied include/secrets.example.h -> include/secrets.h (edit with your credentials)")
