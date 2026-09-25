import QtQuick
import qs.Commons
import qs.Ui

// Answers one credential prompt from NetworkManager. When the current
// prompt looks like a username (plaintext), a second "Password" field is
// shown alongside it too — OpenConnect/GlobalProtect almost always ask for
// both in that order, and waiting through two separate round trips just to
// type two fields is unnecessary. The first field's answer goes out
// immediately on submit; the second is buffered by the caller (see
// Panel.qml's _pendingAutoAnswer) and supplied the instant the real
// password prompt arrives, with no further prompt shown for it.
Column {
  id: root

  property var prompt: null
  property color foreground: Color.foreground
  property color dim: Qt.darker(foreground, 1.55)
  property string fontFamily: Style.font.family

  readonly property string promptId: prompt ? prompt.id : ""
  readonly property bool showSecondField: prompt !== null && prompt.secret !== true

  signal submitted(string text, string secondText)
  signal cancelled()

  visible: prompt !== null
  spacing: Style.space(6)

  // A new prompt (e.g. OTP after password) must not inherit the last answer.
  onPromptIdChanged: {
    field.text = ""
    secondField.text = ""
    // Deferred: forceActiveFocus() called synchronously, the same frame this
    // item becomes visible, silently fails to take — the field never gets
    // focus and every keystroke goes to the (blocked, so silently-dropped)
    // PanelKeyCatcher instead. Matches KeyboardPanel's own focus-prime timing.
    if (promptId !== "") Qt.callLater(function() { field.forceActiveFocus() })
  }

  function submit() {
    root.submitted(field.text, showSecondField ? secondField.text : "")
    field.text = ""
    secondField.text = ""
  }

  Text {
    width: parent.width
    text: root.prompt ? root.prompt.label : ""
    color: root.foreground
    font.family: root.fontFamily
    font.pixelSize: Style.font.body
    font.bold: true
    wrapMode: Text.WordWrap
  }

  TextField {
    id: field
    width: parent.width
    foreground: root.foreground
    password: root.prompt ? root.prompt.secret : true
    KeyNavigation.tab: root.showSecondField ? secondField : field
    onAccepted: root.showSecondField ? secondField.forceActiveFocus() : root.submit()
    Keys.onEscapePressed: root.cancelled()

    // Matches network's wifi-passphrase field exactly (the proven pattern
    // for an inline TextField in a KeyboardPanel): a single onPromptIdChanged
    // trigger on the container wasn't reliable enough on its own.
    onVisibleChanged: if (visible) Qt.callLater(forceActiveFocus)
    Component.onCompleted: if (visible) Qt.callLater(forceActiveFocus)
  }

  Text {
    width: parent.width
    visible: root.showSecondField
    text: "Password"
    color: root.foreground
    font.family: root.fontFamily
    font.pixelSize: Style.font.body
    font.bold: true
  }

  TextField {
    id: secondField
    width: parent.width
    visible: root.showSecondField
    foreground: root.foreground
    password: true
    KeyNavigation.tab: field
    onAccepted: root.submit()
    Keys.onEscapePressed: root.cancelled()
  }

  Text {
    width: parent.width
    text: root.showSecondField ? "Tab to move · Enter to submit both · Esc to cancel" : "Enter to submit · Esc to cancel"
    color: root.dim
    font.family: root.fontFamily
    font.pixelSize: Style.font.caption
  }

  // Esc/Enter above cover keyboard use, but while a field has focus the
  // panel's own key handling is blocked (see Panel.qml's keyCatcher) — a
  // mouse-only way in is needed too.
  Row {
    spacing: Style.space(8)

    Button {
      text: "Submit"
      bordered: true
      foreground: root.foreground
      fontFamily: root.fontFamily
      onClicked: root.submit()
    }

    Button {
      text: "Cancel"
      bordered: true
      foreground: root.foreground
      fontFamily: root.fontFamily
      onClicked: root.cancelled()
    }
  }
}
