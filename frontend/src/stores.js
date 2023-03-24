import { writable } from "svelte/store";

/***
 * Currently selected resource.
 */
export const selected = writable(undefined);
export const selectedResource = writable(undefined);
export const script = writable([]);

/***
 * Points the OFRAK frontend to a seperate backend server
 * When empty, uses the same host and port as the frontend
 */
export const backendUrl = "//localhost:1666";
