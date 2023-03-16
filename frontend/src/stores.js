import { writable } from "svelte/store";

/***
 * Currently selected resource.
 */
export const selected = writable(undefined);
export const selectedResource = writable(undefined);

/***
 * Points the OFRAK frontend to a seperate backend server
 * When empty, uses the same host and port as the frontend
 */
export const backendUrl = "";
