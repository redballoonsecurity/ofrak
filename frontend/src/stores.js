import { animals, otherColors } from "./animals.js";

import { writable } from "svelte/store";

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
    selected: otherColors[0],
    highlight: otherColors[1],
    comment: "#eb8e5b",
    colors: otherColors, // animals.map(a => a.color).concat(otherColors),

    // Points the OFRAK frontend to a seperate backend server. When empty, uses
    // the same host and port as the frontend.
    backendUrl: "",
  };

  if (forceReset) {
    return defaultSettings;
  }
  try {
    return (
      JSON.parse(window.localStorage.getItem("settings")) || defaultSettings
    );
  } catch {
    return defaultSettings;
  }
}

export let settings = writable(loadSettings());
