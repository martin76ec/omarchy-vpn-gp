import QtQuick
import Quickshell.Io
import qs.Commons
import qs.Ui
import "Model.js" as Model
import "components"

Panel {
  id: root
  moduleName: "dev.martin.global-connect"
  manageIpc: false

  property var anchorItem: null
  property var hostWidget: null

  property string vpnState: "DISCONNECTED"
  property string activeId: ""
  property string activeName: ""
  property var profiles: []
  property int selectedIndex: 0
  property string notice: ""
  // notice doubles as both a benign confirmation ("Saved credentials for
  // X.", a server-check result) and an actual failure message — this flag
  // is the only thing telling those apart for coloring; without it a
  // success notice paints in the same urgent/red as a real error and reads
  // as one, especially sitting right next to a just-succeeded "Connected".
  property bool noticeIsError: false
  property string statusError: ""
  property bool backendReady: false
  property var prompt: null
  // Mirrors status.verifying/verified (core/drivers/nm_driver.py's Status):
  // a "v" run reuses the same AUTHENTICATING/prompt machinery as connect,
  // distinguished only by these two fields. verified is tri-state: null
  // (no verify has landed since the last poll cycle), true (saved), false
  // (failed — see statusError for why).
  property bool verifying: false
  property var verified: null
  property var rate: null
  property var latencyMs: null
  property var _sample: null
  property string _answeredPromptId: ""
  // Typed alongside a plaintext (username-like) prompt's answer, and fed to
  // the very next prompt the instant it arrives — see AuthModal.qml.
  property string _pendingAutoAnswer: ""
  property var _queuedSubmission: null
  property bool adding: false
  property bool addBusy: false
  property string addError: ""
  property string _deleteId: ""

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  readonly property string barLabel: Model.barLabel(vpnState, activeName, spinner)
  readonly property bool vpnActive: vpnState === "CONNECTED"
  readonly property bool busy: Model.isPending(vpnState)
  readonly property string message: notice !== "" ? notice : statusError
  readonly property color messageColor: notice !== "" && !noticeIsError ? root.dim : root.urgent
  readonly property string telemetryText: Model.telemetryLine(rate, latencyMs)
  readonly property string stateLabel: Model.stateLabel(vpnState, prompt !== null, verifying)
  readonly property string tooltip: stateLabel + (activeName ? " — " + activeName : "")
    + (telemetryText !== "" ? "\n" + telemetryText : "")

  readonly property var _spinnerFrames: ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
  property int _spinnerIndex: 0
  readonly property string spinner: busy ? _spinnerFrames[_spinnerIndex] : ""

  Timer {
    interval: 90
    running: root.busy
    repeat: true
    onTriggered: root._spinnerIndex = (root._spinnerIndex + 1) % root._spinnerFrames.length
  }
  readonly property string helperPath: decodeURIComponent(
    Qt.resolvedUrl("bin/omarchy-vpn-helper").toString().replace(/^file:\/\//, ""))

  property var _queue: []
  property var _job: null

  function open() { root.controller.show() }
  function close() { root.controller.hide() }
  function switchPanel(direction) {
    if (root.bar && typeof root.bar.switchPanelFrom === "function")
      return root.bar.switchPanelFrom(root.hostWidget || root, direction)
    return false
  }

  // One helper process at a time, and never two queued jobs with the same
  // tag, so a slow nmcli cannot pile up behind the poll timer.
  function request(tag, args, handler) {
    if ((_job && _job.tag === tag) || _queue.some(function(job) { return job.tag === tag })) return
    _queue.push({ tag: tag, args: args, handler: handler })
    pump()
  }

  function pump() {
    if (helper.running || _queue.length === 0) return
    _job = _queue.shift()
    helper.command = ["python3", helperPath].concat(_job.args)
    helper.running = true
  }

  function refreshStatus() { request("status", ["status"], applyStatus) }
  function refreshProfiles() { request("list", ["list"], applyProfiles) }
  function refresh() { refreshProfiles(); refreshStatus() }

  function applyStatus(response) {
    root.backendReady = response.ok
    if (!response.ok) {
      root.notice = Model.errorMessage(response)
      root.noticeIsError = true
      return
    }
    var previousState = root.vpnState
    var previousVerified = root.verified
    root.vpnState = response.state
    root.activeId = response.profile_id || ""
    root.activeName = response.profile_name || ""
    root.statusError = response.error ? response.error.message : ""
    root.verifying = !!response.verifying
    root.verified = response.verified === undefined ? null : response.verified
    // Fires exactly once per verify: the "verified" record lingers across
    // polls the same way a connect "failure" does (see activation.observe),
    // so gate on the transition rather than the level to avoid re-notifying.
    if (root.verified === true && previousVerified !== true) {
      root.notice = "Saved credentials for " + (response.profile_name || "this profile") + "."
      root.noticeIsError = false
    }
    // The prompt lingers until the watcher consumes our answer; do not
    // resurrect one we already submitted.
    var next = response.prompt && response.prompt.id !== root._answeredPromptId ? response.prompt : null
    // A second field typed alongside the previous prompt: answer this one
    // straight away, with no round trip through the panel at all.
    if (next && root._pendingAutoAnswer !== "") {
      root._answeredPromptId = next.id
      root.submitCredentials(next.id, root._pendingAutoAnswer)
      root._pendingAutoAnswer = ""
      next = null
    }
    // A prompt raised while the panel is closed would otherwise sit unseen
    // until NetworkManager gives up on the secret request. Same for the
    // outcome once the attempt lands (CONNECTED or ERROR): closing the
    // panel after clicking connect must not hide how it turned out.
    var isNew = next !== null && (root.prompt === null || root.prompt.id !== next.id)
    var justLanded = previousState !== response.state && (response.state === "CONNECTED" || response.state === "ERROR")
    root.prompt = next
    if ((isNew || justLanded) && !root.opened) root.open()
    if (response.state !== "CONNECTED") {
      root._sample = null
      root.rate = null
      root.latencyMs = null
    }
  }

  function applyTelemetry(response) {
    if (!response.ok) return
    var sample = { rx: response.rx_bytes, tx: response.tx_bytes, at: Date.now() }
    root.rate = Model.rates(root._sample, sample)
    root._sample = sample
    root.latencyMs = response.latency_ms
  }

  function applyProfiles(response) {
    if (!response.ok) {
      root.notice = Model.errorMessage(response)
      root.noticeIsError = true
      return
    }
    root.profiles = response.profiles
    root.selectedIndex = Model.step(root.selectedIndex, 0, response.profiles.length)
  }

  function applyAction(response) {
    if (!response.ok) {
      root.notice = Model.errorMessage(response)
      root.noticeIsError = true
      // Reconciles the optimistic CONNECTING set by connectProfile/
      // verifyCredentials below when the backend actually rejected it (e.g.
      // a race lost to the FSM) — without this the panel would be stuck
      // showing a spinner that nothing is ever going to resolve.
      refreshStatus()
      return
    }
    root.notice = ""
    root.vpnState = response.state
    refreshStatus()
  }

  // Sets CONNECTING immediately rather than waiting for the round trip
  // (connect/verify block for up to a second to catch early failures — see
  // bin/omarchy-vpn-helper's EARLY_FAILURE_WINDOW) so pressing a profile
  // shows a spinner right away instead of a dead click; applyAction
  // reconciles with the real state as soon as the response lands either way.
  function connectProfile(profile) {
    root.notice = ""
    root.noticeIsError = false
    root._pendingAutoAnswer = ""
    root._queuedSubmission = null
    root.vpnState = "CONNECTING"
    root.activeId = profile.id
    root.activeName = profile.name
    request("action", ["connect", profile.id], applyAction)
  }

  function verifyCredentials(profile) {
    if (Model.isPending(root.vpnState) && !Model.isActive(root.vpnState)) return
    if (root.vpnState !== "DISCONNECTED" && root.vpnState !== "ERROR") {
      root.notice = "Disconnect the active VPN first."
      root.noticeIsError = true
      return
    }
    root.notice = ""
    root.noticeIsError = false
    root._pendingAutoAnswer = ""
    root._queuedSubmission = null
    root.vpnState = "CONNECTING"
    root.verifying = true
    root.activeId = profile.id
    root.activeName = profile.name
    request("action", ["verify", profile.id], applyAction)
  }

  function testServer(profile) {
    root.notice = "Checking " + profile.name + "…"
    root.noticeIsError = false
    request("testServer", ["test-server", profile.id], applyTestServer)
  }

  function applyTestServer(response) {
    root.notice = response.ok ? Model.serverCheckLabel(response) : Model.errorMessage(response)
    root.noticeIsError = !response.ok || !response.reachable
  }

  function disconnect() {
    root.notice = ""
    root.noticeIsError = false
    root._pendingAutoAnswer = ""
    root._queuedSubmission = null
    request("action", ["disconnect"], applyAction)
  }

  function activate(index) {
    root.selectedIndex = index
    var profile = root.profiles[index]
    if (!profile || Model.isPending(root.vpnState) && !Model.isActive(root.vpnState)) return
    if (Model.isActive(root.vpnState) && profile.id === root.activeId) return disconnect()
    // ERROR is retryable: connect clears the recorded failure.
    if (root.vpnState !== "DISCONNECTED" && root.vpnState !== "ERROR") {
      root.notice = "Disconnect the active VPN first."
      root.noticeIsError = true
      return
    }
    connectProfile(profile)
  }

  function toggleConnection() {
    if (Model.isActive(root.vpnState)) return disconnect()
    activate(root.selectedIndex)
  }

  // The secret travels panel -> helper stdin only; never argv.
  //
  // Queues rather than drops when a submission is already in flight: the
  // auto-answered second field (see AuthModal.qml) can arrive before the
  // first field's own `credentials` process has finished exiting, and a
  // dropped auto-answer left the backend waiting forever for a prompt the
  // panel had already stopped showing.
  function submitCredentials(promptId, secret) {
    if (credentials.running) {
      root._queuedSubmission = { promptId: promptId, secret: secret }
      return
    }
    credentials.command = ["python3", helperPath, "credentials", promptId]
    credentials.secret = secret
    credentials.running = true
  }

  function startAdding() {
    root.addError = ""
    root.adding = true
  }

  // JSON goes over stdin (one line), the same channel credentials use.
  function submitProfile(request) {
    if (adder.running) return
    root.addError = ""
    root.addBusy = true
    adder.command = ["python3", helperPath, "add"]
    adder.payload = JSON.stringify(request)
    adder.running = true
  }

  function applyAdd(response) {
    root.addBusy = false
    if (!response.ok) {
      root.addError = Model.errorMessage(response)
      return
    }
    root.adding = false
    refreshProfiles()
  }

  // Two presses on the same row: a mistyped key must not delete a profile.
  function requestDelete() {
    var profile = root.profiles[root.selectedIndex]
    if (!profile) return
    if (root._deleteId !== profile.id) {
      root._deleteId = profile.id
      root.notice = "Press x again to delete “" + profile.name + "”."
      root.noticeIsError = true
      return
    }
    root._deleteId = ""
    root.notice = ""
    root.noticeIsError = false
    request("action", ["delete", profile.id], function(response) {
      if (!response.ok) {
        root.notice = Model.errorMessage(response)
        root.noticeIsError = true
      }
      refreshProfiles()
    })
  }

  onOpenedChanged: if (opened) {
    root.adding = false
    root._deleteId = ""
    root.notice = ""
    root.noticeIsError = false
    refresh()
  }

  Timer {
    interval: root.opened || Model.isPending(root.vpnState) ? 1500 : 5000
    running: true
    repeat: true
    triggeredOnStart: true
    onTriggered: root.refreshStatus()
  }

  Timer {
    interval: root.opened ? 2000 : 10000
    running: root.vpnState === "CONNECTED"
    repeat: true
    triggeredOnStart: true
    onTriggered: root.request("telemetry", ["telemetry"], root.applyTelemetry)
  }

  Process {
    id: adder
    property string payload: ""
    stdinEnabled: true
    stdout: StdioCollector {
      id: adderOut
      waitForEnd: true
      onStreamFinished: adder.captured = text
    }
    property string captured: ""
    onStarted: write(payload + "\n")
    onExited: {
      root.applyAdd(Model.parseResponse(String(adderOut.text || adder.captured)))
      captured = ""
    }
  }

  Process {
    id: credentials
    property string secret: ""
    stdinEnabled: true
    onStarted: {
      write(secret + "\n")
      secret = ""
    }
    onExited: {
      root.refreshStatus()
      if (root._queuedSubmission) {
        var queued = root._queuedSubmission
        root._queuedSubmission = null
        root.submitCredentials(queued.promptId, queued.secret)
      }
    }
  }

  Process {
    id: helper
    property string captured: ""
    stdout: StdioCollector {
      id: collector
      waitForEnd: true
      onStreamFinished: helper.captured = text
    }
    onExited: {
      var job = root._job
      var response = Model.parseResponse(String(collector.text || helper.captured))
      helper.captured = ""
      root._job = null
      job.handler(response)
      root.pump()
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root.hostWidget || root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(320))
    contentHeight: panel.fittedContentHeight(content.implicitHeight)

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      blocked: root.prompt !== null || root.adding
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onMoveRequested: function(dx, dy) {
        root._deleteId = ""
        root.selectedIndex = Model.step(root.selectedIndex, dy, root.profiles.length)
      }
      onActivateRequested: root.activate(root.selectedIndex)
      onDeleteRequested: root.requestDelete()
      onTextKey: function(key) {
        var selected = root.profiles[root.selectedIndex]
        if (key === "t") root.toggleConnection()
        else if (key === "r") root.refresh()
        else if (key === "a") root.startAdding()
        else if (key === "s" && selected) root.testServer(selected)
        else if (key === "v" && selected) root.verifyCredentials(selected)
      }

      Column {
        id: content
        width: parent.width
        spacing: Style.space(8)

        Row {
          width: parent.width
          spacing: Style.space(6)

          Text {
            visible: root.busy
            text: root.spinner
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.heading
          }

          Text {
            text: root.stateLabel
            color: root.vpnState === "CONNECTED" ? root.foreground : root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.heading
            font.bold: true
          }
        }

        Text {
          width: parent.width
          visible: root.activeName !== ""
          text: root.activeName
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          elide: Text.ElideRight
        }

        Text {
          width: parent.width
          visible: root.vpnState === "CONNECTED" && root.telemetryText !== ""
          text: root.telemetryText
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.bodySmall
        }

        AddProfileModal {
          width: parent.width
          active: root.adding
          busy: root.addBusy
          error: root.addError
          foreground: root.foreground
          urgent: root.urgent
          dim: root.dim
          fontFamily: root.fontFamily
          onSubmitted: function(request) { root.submitProfile(request) }
          // Deferred: clearing `adding` synchronously flips keyCatcher's
          // `blocked` back to false while THIS SAME Escape keypress is
          // still propagating (PanelKeyCatcher's Keys.priority: BeforeItem
          // gives it a pass before the field, then the normal bubble-up
          // gives it another after) — letting one keystroke fire twice,
          // the second time unblocked. See AuthModal's onSubmitted for the
          // confirmed repro of this exact race.
          onCancelled: Qt.callLater(function() { root.adding = false })
        }

        AuthModal {
          width: parent.width
          prompt: root.prompt
          foreground: root.foreground
          dim: root.dim
          fontFamily: root.fontFamily
          onSubmitted: function(text, secondText) {
            root._answeredPromptId = root.prompt.id
            root.submitCredentials(root.prompt.id, text)
            root._pendingAutoAnswer = secondText
            // Deferred: confirmed via live debug logging that clearing
            // `prompt` here synchronously flips keyCatcher.blocked back to
            // false while this same Enter keypress is still propagating,
            // so the very keystroke that submitted the form also reaches
            // keyCatcher a second time — unblocked — firing
            // activateRequested() and disconnecting the attempt that was
            // just started. Deferring the unblock to the next tick lets
            // this event finish propagating first.
            Qt.callLater(function() { root.prompt = null })
          }
          onCancelled: root.disconnect()
        }

        Text {
          width: parent.width
          visible: root.message !== ""
          text: root.message
          color: root.messageColor
          font.family: root.fontFamily
          font.pixelSize: Style.font.bodySmall
          wrapMode: Text.WordWrap
        }

        PanelSeparator { foreground: root.foreground }

        PanelSectionHeader {
          text: "PROFILES"
          foreground: root.foreground
          fontFamily: root.fontFamily
        }

        Text {
          width: parent.width
          visible: root.backendReady && root.profiles.length === 0
          text: "No OpenConnect or OpenVPN profiles yet. Press a to add one."
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.bodySmall
          wrapMode: Text.WordWrap
        }

        Repeater {
          model: root.profiles

          Rectangle {
            id: row
            required property var modelData
            required property int index
            readonly property bool selected: index === root.selectedIndex
            readonly property bool current: Model.isActive(root.vpnState) && modelData.id === root.activeId

            width: content.width
            height: Math.max(rowLayout.implicitHeight, actions.implicitHeight) + Style.space(12)
            radius: Style.cornerRadius
            color: selected
              ? Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.12)
              : "transparent"

            Row {
              id: rowLayout
              anchors.verticalCenter: parent.verticalCenter
              anchors.left: parent.left
              anchors.leftMargin: Style.space(8)
              spacing: Style.space(8)

              Text {
                text: "[" + Model.badge(row.modelData) + "]"
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
              }

              Text {
                text: row.modelData.name
                color: row.current ? root.foreground : root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
                font.bold: row.current
              }

              Text {
                visible: !!row.modelData.has_saved_credentials
                text: "saved"
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }
            }

            MouseArea {
              anchors.fill: parent
              onClicked: root.activate(row.index)
            }

            // Declared after the row-select MouseArea above so these sit on
            // top of it in paint/hit-test order and take their own clicks;
            // everywhere else on the row still falls through to select/connect.
            Row {
              id: actions
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              anchors.rightMargin: Style.space(8)
              spacing: Style.space(6)

              Button {
                text: "Test"
                tooltipText: "Check if the server is reachable"
                bordered: true
                foreground: root.dim
                fontFamily: root.fontFamily
                fontSize: Style.font.caption
                horizontalPadding: Style.space(6)
                verticalPadding: Style.space(2)
                onClicked: root.testServer(row.modelData)
              }

              Button {
                visible: row.modelData.engine === "openconnect"
                text: "Verify"
                tooltipText: "Confirm the login works, then save it so connecting never asks again"
                bordered: true
                foreground: root.dim
                fontFamily: root.fontFamily
                fontSize: Style.font.caption
                horizontalPadding: Style.space(6)
                verticalPadding: Style.space(2)
                onClicked: root.verifyCredentials(row.modelData)
              }
            }
          }
        }

        PanelSeparator { foreground: root.foreground }

        Text {
          width: parent.width
          text: "j/k move · Enter connect/disconnect · s test server · v verify+save · a add · x delete · r refresh · Esc close"
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
        }
      }
    }
  }
}
