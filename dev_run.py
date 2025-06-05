
import subprocess
import time
import os

main_script = "main.py"

def run_bot():
    return subprocess.Popen(["python", main_script])

def get_mtime(path):
    return os.path.getmtime(path)

def watch_and_reload():
    last_mtime = get_mtime(main_script)
    p = run_bot()
    print("🚀 Bot started. Watching for changes...")

    try:
        while True:
            time.sleep(1)
            new_mtime = get_mtime(main_script)
            if new_mtime != last_mtime:
                print("🔄 Change detected! Restarting bot...")
                p.terminate()
                p = run_bot()
                last_mtime = new_mtime
    except KeyboardInterrupt:
        print("🛑 Stopping...")
        p.terminate()

if __name__ == "__main__":
    watch_and_reload()
