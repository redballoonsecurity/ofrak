export const shortcuts = {};

/***
 * Turn a keyboard event into a canonicalized string. This is necessary for
 * using key events as object property names.
 */
export function keyEventToString(e) {
  const { key, altKey, ctrlKey, metaKey, shiftKey } = e;
  let modifiers = [];
  if (altKey) {
    modifiers.push("Alt");
  }
  if (ctrlKey) {
    modifiers.push("Ctrl");
  }
  if (metaKey) {
    modifiers.push("Meta");
  }
  if (shiftKey) {
    modifiers.push("Shift");
  }
  const modifierString = modifiers.sort().join("+");
  return key.toLocaleLowerCase() + (modifierString ? "+" + modifierString : "");
}
