import QtQuick
import qs.Commons
import qs.Ui
import "../Model.js" as Model

// Collects a new profile. Nothing is validated here beyond "not empty": the
// helper is the trust boundary and reports precise errors back via `error`.
Column {
  id: root

  property bool active: false
  property bool busy: false
  property string error: ""
  property color foreground: Color.foreground
  property color urgent: Color.urgent
  property color dim: Qt.darker(foreground, 1.55)
  property string fontFamily: Style.font.family

  property int typeIndex: 0
  readonly property var type: Model.PROFILE_TYPES[typeIndex]

  signal submitted(var request)
  signal cancelled()

  visible: active
  spacing: Style.space(6)

  onActiveChanged: if (active) {
    nameField.text = ""
    serverField.text = ""
    // Deferred: see AuthModal.qml's onPromptIdChanged for why a synchronous
    // forceActiveFocus() here silently fails to take.
    Qt.callLater(function() { nameField.forceActiveFocus() })
  }

  function step(delta) {
    typeIndex = Model.cycle(typeIndex, delta, Model.PROFILE_TYPES.length)
  }

  function submit() {
    if (busy || !Model.canSubmit(typeIndex, nameField.text, serverField.text)) return
    root.submitted(Model.addRequest(typeIndex, nameField.text, serverField.text))
  }

  Text {
    width: parent.width
    text: "Add profile"
    color: root.foreground
    font.family: root.fontFamily
    font.pixelSize: Style.font.body
    font.bold: true
  }

  Row {
    spacing: Style.space(8)

    Text {
      text: "‹"
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.title
      MouseArea { anchors.fill: parent; anchors.margins: -Style.space(4); onClicked: root.step(-1) }
    }
    Text {
      text: root.type.label
      color: root.foreground
      font.family: root.fontFamily
      font.pixelSize: Style.font.body
    }
    Text {
      text: "›"
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.title
      MouseArea { anchors.fill: parent; anchors.margins: -Style.space(4); onClicked: root.step(1) }
    }
  }

  TextField {
    id: nameField
    width: parent.width
    foreground: root.foreground
    placeholderText: root.type.kind === "openvpn" ? "Name (optional)" : "Name"
    KeyNavigation.tab: serverField
    Keys.onUpPressed: root.step(-1)
    Keys.onDownPressed: root.step(1)
    Keys.onEscapePressed: root.cancelled()
    onAccepted: serverField.text === "" ? serverField.forceActiveFocus() : root.submit()

    // Matches network's wifi-passphrase field exactly (the proven pattern
    // for an inline TextField in a KeyboardPanel): a single onActiveChanged
    // trigger on the container wasn't reliable enough on its own.
    onVisibleChanged: if (visible) Qt.callLater(forceActiveFocus)
    Component.onCompleted: if (visible) Qt.callLater(forceActiveFocus)
  }

  TextField {
    id: serverField
    width: parent.width
    foreground: root.foreground
    placeholderText: root.type.field + " — " + root.type.placeholder
    KeyNavigation.tab: nameField
    Keys.onUpPressed: root.step(-1)
    Keys.onDownPressed: root.step(1)
    Keys.onEscapePressed: root.cancelled()
    onAccepted: root.submit()
  }

  Text {
    width: parent.width
    visible: root.error !== ""
    text: root.error
    color: root.urgent
    font.family: root.fontFamily
    font.pixelSize: Style.font.bodySmall
    wrapMode: Text.WordWrap
  }

  Text {
    width: parent.width
    text: root.busy ? "Adding…" : "↑/↓ type · Tab next field · Enter add · Esc cancel"
    color: root.dim
    font.family: root.fontFamily
    font.pixelSize: Style.font.caption
    wrapMode: Text.WordWrap
  }
}
