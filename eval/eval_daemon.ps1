# Detached eval daemon: survives opencode/server restarts because Windows
# Task Scheduler parents it, not the coding agent's shell.
#
# Loop: ensure Ollama serve + lab vulnserver are listening, run the eval,
# stop when a fresh scorecard JSON appears; otherwise retry (a killed run's
# stage checkpoints still persist cassettes + state-latest.json).
$log     = "C:\dev\obsidian-os\redteam-agents\artifacts\eval_daemon.log"
$scoreDir= "C:\dev\obsidian-os\redteam-agents\artifacts\eval\lab"
$root    = "C:\dev\obsidian-os\redteam-agents"
$ollama  = "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe"

function Log($m){ Add-Content -Path $log -Value ("[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $m) }

# crude single-instance lock: refuse if a marker younger than 6h exists
$lock = "C:\dev\obsidian-os\redteam-agents\artifacts\eval_daemon.lock"
if (Test-Path $lock) {
    $age = (Get-Date) - (Get-Item $lock).LastWriteTime
    if ($age.TotalHours -lt 6) { Log "another daemon instance looks active (lock age $([int]$age.TotalMinutes) min) - exiting"; exit 0 }
}
New-Item -Path $lock -ItemType File -Force | Out-Null
Log "=== daemon start ==="

$up = $false
for ($i = 1; $i -le 8 -and -not $up; $i++) {
    $started = Get-Date
    Log "--- attempt $i ---"
    try {
        # ollama
        $ollamaUp = $false
        try { Invoke-WebRequest -Uri "http://127.0.0.1:11434/api/tags" -UseBasicParsing -TimeoutSec 4 | Out-Null; $ollamaUp = $true } catch {}
        if (-not $ollamaUp) {
            Log "starting ollama serve (MAX_LOADED_MODELS=1: 16GB host cannot keep both runners hot)"
            $cmdLine = 'set OLLAMA_MAX_LOADED_MODELS=1&& "' + $ollama + '" serve'
            Start-Process -FilePath "cmd.exe" -ArgumentList $cmdLine -WindowStyle Hidden
            Start-Sleep -Seconds 6
        }
        # lab server
        $labUp = $false
        try { Invoke-WebRequest -Uri "http://127.0.0.1:8000/robots.txt" -UseBasicParsing -TimeoutSec 4 | Out-Null; $labUp = $true } catch {}
        if (-not $labUp) {
            Log "starting lab vulnserver"
            Start-Process -FilePath "python" -ArgumentList "lab\vulnserver.py", "--port", "8000" -WorkingDirectory $root -WindowStyle Hidden
            Start-Sleep -Seconds 3
        }

        Log "launching eval (record mode)"
        # Task Scheduler starts us in system32 — pin the eval's CWD to the
        # project root (run_eval, config and artifacts paths are relative).
        Push-Location $root
        try {
            $out = & python eval\run_eval.py --config config.yaml --target lab --mode record --yes --allow-active 2>&1
        } finally { Pop-Location }
        $out | ForEach-Object { Log "  | $_" }
        $code = $LASTEXITCODE

        $fresh = Get-ChildItem -Path $scoreDir -Filter "eval-lab-*.json" -ErrorAction SilentlyContinue |
                 Where-Object { $_.LastWriteTime -gt $started.AddMinutes(-3) } |
                 Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($fresh) {
            Log "scorecard produced: $($fresh.Name) - DONE"
            $up = $true
        } elseif ($code -eq 0) {
            Log "exit 0 but no fresh scorecard - unexpected; retrying"
        } else {
            Log "eval exited code $code without scorecard; retrying in 45s"
            Start-Sleep -Seconds 45
        }
    } catch {
        Log "attempt crashed: $_ ; retrying in 45s"
        Start-Sleep -Seconds 45
    }
}
Remove-Item $lock -ErrorAction SilentlyContinue
Log "=== daemon end (done=$up) ==="
