import
  std/[
    asyncdispatch, asyncnet, json, os, osproc, streams, strtabs, strutils, tempfiles,
    unittest,
  ]
from std/nativesockets import AF_UNIX, SOCK_STREAM, IPPROTO_IP
from posix import kill, Pid, SIGTERM
import ../src/utils/runtime_deadlines
import
  ../src/session/
    [logs, session_control, session_control_client, shell_manager, supervisor]

proc runFakeDaemon(): int =
  ## Stands in for the daemon: records the first IPC line, then exits cleanly.
  let server = newAsyncSocket(AF_UNIX, SOCK_STREAM, IPPROTO_IP)
  server.bindUnix(getEnv("XDG_RUNTIME_DIR") / "triad.sock")
  server.listen()
  let client = waitFor server.accept()
  writeFile(getEnv("TRIAD_TEST_HANDOFF"), waitFor client.recvLine())
  0

if paramCount() == 1:
  case paramStr(1)
  of "--test-supervisor":
    quit runSupervisor()
  of "--test-shell-manager":
    quit runShellManager()
  of "--test-fake-daemon":
    quit runFakeDaemon()
  else:
    discard

suite "session control protocol":
  test "round-trips a versioned message":
    let line = encodeSessionControl(SessionControlKind.SpawnStarted, %*{"pid": 4321})
    let decoded = decodeSessionControl(line)
    check decoded.ok
    check decoded.message.version == SessionControlProtocolVersion
    check decoded.message.kind == SessionControlKind.SpawnStarted
    check decoded.message.payload["pid"].getInt() == 4321

  test "rejects a mismatched protocol version":
    let line = """{"version":1,"kind":"Shutdown","payload":{}}""" & "\n"
    let decoded = decodeSessionControl(line)
    check not decoded.ok
    check decoded.error.contains("version")

  test "rejects oversized lines":
    let line = repeat("x", MaxSessionControlLineBytes + 1)
    let decoded = decodeSessionControl(line)
    check not decoded.ok
    check decoded.error.contains("length")

  test "rejects unknown control kinds":
    let line = """{"version":2,"kind":"Nope","payload":{}}""" & "\n"
    let decoded = decodeSessionControl(line)
    check not decoded.ok
    check decoded.error.contains("kind")

  test "only allows the expected peer uid":
    check sessionControlPeerAllowed(1000, 1000)
    check not sessionControlPeerAllowed(1001, 1000)
    check not sessionControlPeerAllowed(-1, -1)

  test "rejects non-object payloads":
    let line = """{"version":2,"kind":"Shutdown","payload":[]}""" & "\n"
    let decoded = decodeSessionControl(line)
    check not decoded.ok
    check decoded.error.contains("payload")

suite "session claim records":
  test "claim is held only while its claim id remains current":
    let dir = getTempDir() / ("triad-session-claim-" & $getCurrentProcessId())
    if dirExists(dir):
      removeDir(dir)
    createDir(dir)
    defer:
      if dirExists(dir):
        removeDir(dir)

    let path = dir / "current-session.json"
    writeFile(path, """{"claim_id":"claim-a"}""")
    let claim = SessionClaim(path: path, claimId: "claim-a")
    check sessionClaimHeld(claim)

    writeFile(path, """{"claim_id":"claim-b"}""")
    check not sessionClaimHeld(claim)

suite "supervised shell recovery":
  test "rapid shell-manager failures share the supervisor restart backoff":
    let dir = createTempDir("triad-shell-recovery-", "")
    defer:
      removeDir(dir)
    let fakeTriad = dir / "fake-triad"
    let restarts = dir / "restarts"
    writeFile(
      fakeTriad,
      """#!/bin/sh
if [ "$1" = shell-manager ]; then
    printf 'start\n' >> "$TRIAD_TEST_RESTARTS"
    exit 1
fi
exec sleep 30
""",
    )
    setFilePermissions(fakeTriad, {fpUserRead, fpUserWrite, fpUserExec})
    let env = newStringTable(modeCaseSensitive)
    for key, value in envPairs():
      env[key] = value
    env["XDG_STATE_HOME"] = dir
    # Keep the supervisor away from a live session's IPC socket.
    env["XDG_RUNTIME_DIR"] = dir
    env["TRIAD_BIN"] = fakeTriad
    env["TRIAD_TEST_RESTARTS"] = restarts

    let process = startProcess(
      getAppFilename(),
      args = ["--test-supervisor"],
      env = env,
      options = {poStdErrToStdOut},
    )
    defer:
      process.close()
    var launches = 0
    let deadline = monotonicMs() + 10_000
    try:
      while monotonicMs() < deadline and process.peekExitCode() == -1:
        if fileExists(restarts):
          launches = readFile(restarts).count("start")
          if launches >= 3:
            break
        sleep(25)
    finally:
      if process.peekExitCode() == -1:
        process.terminate()
        if process.waitForExit(4000) == -1:
          process.kill()
          discard process.waitForExit()
    let output = process.outputStream().readAll()
    check launches >= 3
    check output.contains("restarting session components in 1000 ms")
    check output.contains("restarting session components in 2000 ms")

  test "a shell-manager exit lets the daemon save a restore point first":
    let dir = createTempDir("triad-manager-handoff-", "")
    defer:
      removeDir(dir)
    let fakeTriad = dir / "fake-triad"
    let handoff = dir / "handoff"
    writeFile(
      fakeTriad,
      """#!/bin/sh
if [ "$1" = shell-manager ]; then
    [ -e "$TRIAD_TEST_HANDOFF" ] && exec sleep 30
    sleep 1
    exit 1
fi
exec "$TRIAD_TEST_SELF" --test-fake-daemon
""",
    )
    setFilePermissions(fakeTriad, {fpUserRead, fpUserWrite, fpUserExec})
    let env = newStringTable(modeCaseSensitive)
    for key, value in envPairs():
      env[key] = value
    env["XDG_STATE_HOME"] = dir
    env["XDG_RUNTIME_DIR"] = dir
    env["TRIAD_BIN"] = fakeTriad
    env["TRIAD_TEST_SELF"] = getAppFilename()
    env["TRIAD_TEST_HANDOFF"] = handoff

    let process = startProcess(
      getAppFilename(),
      args = ["--test-supervisor"],
      env = env,
      options = {poStdErrToStdOut},
    )
    defer:
      process.close()
    let deadline = monotonicMs() + 10_000
    try:
      while monotonicMs() < deadline and process.peekExitCode() == -1:
        if fileExists(handoff) and readFile(handoff).len > 0:
          break
        sleep(25)
      sleep(200)
    finally:
      if process.peekExitCode() == -1:
        process.terminate()
        if process.waitForExit(4000) == -1:
          process.kill()
          discard process.waitForExit()
    let output = process.outputStream().readAll()
    check fileExists(handoff)
    check readFile(handoff) == "triad-reload"
    check output.contains("shell manager exited; restarting session components")
    check not output.contains("did not hand off")

  test "the manager acknowledges failed spawns and lets launched apps survive":
    let dir = createTempDir("triad-shell-app-", "")
    defer:
      removeDir(dir)
    let env = newStringTable(modeCaseSensitive)
    for key, value in envPairs():
      env[key] = value
    env["XDG_STATE_HOME"] = dir
    let manager = startProcess(
      getAppFilename(),
      args = ["--test-shell-manager"],
      env = env,
      options = {poParentStreams},
    )
    defer:
      if manager.peekExitCode() == -1:
        manager.terminate()
        if manager.waitForExit(3000) == -1:
          manager.kill()
          discard manager.waitForExit()
      manager.close()

    let client = newSessionControlClient(dir / "triad" / "shell-manager.sock")
    let failed = waitFor client.requestSessionControl(
      SessionControlKind.Spawn,
      SessionControlKind.SpawnStarted,
      %*{"argv": [dir / "missing"]},
      acceptError = true,
    )
    require failed != nil
    check failed.hasKey("error")

    let ack = waitFor client.requestSessionControl(
      SessionControlKind.Spawn,
      SessionControlKind.SpawnStarted,
      %*{"argv": ["/bin/sleep", "15"]},
    )
    require ack != nil
    let pid = Pid(ack{"pid"}.getInt())
    require pid > 0
    defer:
      discard kill(pid, SIGTERM)

    manager.terminate()
    check manager.waitForExit(3000) == 0
    let processStat = readFile("/proc" / $pid / "stat")
    let processState = processStat[processStat.rfind(')') + 2]
    check processState notin {'Z', 'X'}
