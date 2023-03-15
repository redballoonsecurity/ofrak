import { writable } from "svelte/store";

/***
 * Currently selected resource.
 */
export const selected = writable(undefined);
export const selectedResource = writable(undefined);
export const backendUrl = "";
