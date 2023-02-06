import { selected, selectedResource } from "./stores.js";
import { get } from "svelte/store";

export const shortcuts = {
  u: async (resourceNodeDataMap, modifierView) => {
    if (
      !(selected && get(selected) && selectedResource && get(selectedResource))
    ) {
      return;
    }

    await get(selectedResource).unpack();
    resourceNodeDataMap[get(selected)] = {
      collapsed: false,
      childrenPromise: get(selectedResource).get_children(),
    };
  },
};
