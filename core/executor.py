import subprocess


def run_gobuster(mode, url, wordlist, threads):
    command = ["gobuster", mode, "-u", url, "-w", wordlist, "-t", str(threads)]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout if result.returncode == 0 else result.stderr
    except Exception as e:
        return f"Error: {str(e)}"
