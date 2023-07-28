import { animals, otherColors } from "./animals.js";

import { writable } from "svelte/store";
import {blendColors} from "./helpers";

// Currently selected resource ID
export const selected = writable(undefined);

// Currently selected resource object
export const selectedResource = writable(undefined);

// User-generated OFRAK script (array of lines)
export const script = writable([]);

export function loadSettings(forceReset) {
  const defaultSettings = {
    background: "#000000",
    foreground: "#ffffff",
    background_faded: blendColors("#000000", "#ffffff", 0.2),
    foreground_faded: blendColors("#000000", "#ffffff", 0.8),
    selected: otherColors[0],
    highlight: otherColors[1],
    comment: "#eb8e5b",
    lastModified: "#dc4e47",
    allModified: "#fdb44e",
    accentText: animals[1].color,
    colors: otherColors, // animals.map(a => a.color).concat(otherColors),

    experimentalFeatures: false,

    showDevSettings: false,
    // Points the OFRAK frontend to a seperate backend server. When empty, uses
    // the same host and port as the frontend.
    backendUrl: "",
  };

  if (forceReset) {
    return defaultSettings;
  }
  try {
      const prevSettings = JSON.parse(window.localStorage.getItem("settings")) || defaultSettings
      // allows fields in defaultSettings which don't exist in prevSettings (i.e. a new setting has
      // been introduced since user saved their own settings) to still be populated, with default.
      return {...defaultSettings, ...prevSettings}
  } catch {
    return defaultSettings;
  }
}

export let settings = writable(loadSettings());
