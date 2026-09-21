.pragma library

function formatState(state) {
  return state ? state.toLowerCase().replace(/_/g, " ") : "unknown"
}
