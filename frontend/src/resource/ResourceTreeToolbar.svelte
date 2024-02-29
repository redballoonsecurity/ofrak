<script>
  import CarveView from "../views/CarveView.svelte";
  import CommentView from "../views/CommentView.svelte";
  import ComponentsView from "../views/ComponentsView.svelte";
  import ModifyView from "../views/ModifyView.svelte";
  import ScriptView from "../views/ScriptView.svelte";
  import SettingsView from "../views/SettingsView.svelte";
  import SearchView from "../views/SearchView.svelte";
  import AddTagView from "../views/AddTagView.svelte";
  import RunScriptView from "../views/RunScriptView.svelte";
  import Toolbar from "../utils/Toolbar.svelte";

  import {
    selectedResource,
    selected,
    settings,
    selectedProject,
    resourceNodeDataMap,
  } from "../stores.js";

  export let modifierView, bottomLeftPane, showProjectManager, showRootResource;
  $: rootResource = $selectedResource;

  function refreshResource() {
    // Force hex view refresh with colors
    const originalSelected = $selected;
    $selected = undefined;
    $selected = originalSelected;
  }

  let toolbarButtons, experimentalFeatures, projectFeatures;
  const neverResolves = new Promise(() => {});
  $: {
    experimentalFeatures = [
      {
        text: "Run Component",
        iconUrl: "/icons/run.svg",
        onclick: async (e) => {
          modifierView = ComponentsView;
        },
      },

      {
        text: "Run Script",
        iconUrl: "/icons/run_script.svg",
        onclick: async (e) => {
          modifierView = RunScriptView;
        },
      },
    ];
  }

  $: {
    projectFeatures = [
      {
        text: "Project Manager",
        iconUrl: "/icons/briefcase.svg",
        onclick: async (e) => {
          if ($selectedProject) {
            let state = {
              $selectProject: $selectedProject,
            };
            showProjectManager = true;
            showRootResource = false;
            history.pushState(state, "", "/");
          }
        },
      },
    ];
  }

  $: {
    toolbarButtons = [
      {
        text: "Identify",
        iconUrl: "/icons/identify.svg",
        shortcut: "i",
        onclick: async (e) => {
          await rootResource.identify();
          if (!$resourceNodeDataMap[$selected]) {
            $resourceNodeDataMap[$selected] = {};
          }
          $resourceNodeDataMap[$selected].collapsed =
            !!$resourceNodeDataMap[$selected]?.collapsed;
          $resourceNodeDataMap[$selected].childrenPromise =
            rootResource.get_children();
          refreshResource();
        },
      },

      {
        text: "Unpack",
        iconUrl: "/icons/unpack.svg",
        shortcut: "u",
        onclick: async (e) => {
          await rootResource.unpack();
          if (!$resourceNodeDataMap[$selected]) {
            $resourceNodeDataMap[$selected] = {};
          }
          $resourceNodeDataMap[$selected].collapsed = false;
          $resourceNodeDataMap[$selected].childrenPromise =
            rootResource.get_children();
          refreshResource();
        },
      },

      {
        text: "Carve Child",
        iconUrl: "/icons/carve.svg",
        onclick: async (e) => {
          modifierView = CarveView;
        },
      },

      {
        text: "Analyze",
        iconUrl: "/icons/analyze.svg",
        shortcut: "a",
        onclick: async (e) => {
          await rootResource.analyze();
          if (!$resourceNodeDataMap[$selected]) {
            $resourceNodeDataMap[$selected] = {};
          }
          $resourceNodeDataMap[$selected].collapsed =
            !!$resourceNodeDataMap[$selected]?.collapsed;
          $resourceNodeDataMap[$selected].childrenPromise =
            rootResource.get_children();
          refreshResource();
        },
      },

      {
        text: "Modify",
        iconUrl: "/icons/modify.svg",
        onclick: async (e) => {
          modifierView = ModifyView;
        },
      },

      {
        text: "Pack",
        iconUrl: "/icons/pack.svg",
        shortcut: "p",
        onclick: async (e) => {
          const descendants = await $selectedResource.get_descendants();
          clearModified(descendants);
          await rootResource.pack();
          if (!$resourceNodeDataMap[$selected]) {
            $resourceNodeDataMap[$selected] = {};
          }
          $resourceNodeDataMap[$selected].collapsed = false;
          $resourceNodeDataMap[$selected].childrenPromise =
            rootResource.get_children();
          refreshResource();
        },
      },

      {
        text: "Add Tag",
        iconUrl: "/icons/tag.svg",
        onclick: async (e) => {
          modifierView = AddTagView;
        },
      },

      {
        text: "Download",
        iconUrl: "/icons/download.svg",
        onclick: async (e) => {
          if ($selected !== undefined) {
            const data = await rootResource.get_data();
            if (data.length === 0) {
              return;
            }
            const blob = new Blob([data], {
              type:
                rootResource.get_attributes()["ofrak.core.magic.Magic"]?.mime ||
                "",
            });
            const blobUrl = URL.createObjectURL(blob);

            const a = document.createElement("a");
            a.href = blobUrl;
            a.target = "_blank";
            a.download =
              rootResource.get_attributes()[
                "ofrak.model._auto_attributes.AttributesType[FilesystemEntry]"
              ]?.name || "";
            a.click();

            URL.revokeObjectURL(blobUrl);
            await $selectedResource.add_flush_to_disk_to_script(a.download);
          }
        },
      },

      {
        text: "Replace",
        iconUrl: "/icons/upload.svg",
        onclick: async (e) => {
          if ($selected !== undefined) {
            const input = document.createElement("input");
            input.type = "file";
            input.addEventListener(
              "change",
              async () => {
                if (input.files.length > 0) {
                  const file = input.files[0];
                  const data = await file.arrayBuffer();
                  await rootResource.queue_patch(
                    data,
                    0,
                    await rootResource.get_data_length()
                  );
                }
                refreshResource();
              },
              false
            );
            input.click();
            // TODO: Make sure the browser GC collects this closure – don't want
            // it hanging around waiting for a promise that will never resolve
            await neverResolves;
          }
        },
      },

      {
        text: "New",
        iconUrl: "/icons/new.svg",
        shortcut: "n",
        onclick: (e) => {
          // Clear the URL fragment
          window.location.replace("/");
        },
      },

      {
        text: "Unpack Recursively",
        iconUrl: "/icons/unpack_r.svg",
        shortcut: "u+Shift",
        onclick: async (e) => {
          await rootResource.unpack_recursively();
          if (!$resourceNodeDataMap[$selected]) {
            $resourceNodeDataMap[$selected] = {};
          }
          $resourceNodeDataMap[$selected].collapsed = false;
          $resourceNodeDataMap[$selected].childrenPromise =
            rootResource.get_children();
          refreshResource();
        },
      },

      {
        text: "Pack Recursively",
        iconUrl: "/icons/pack_r.svg",
        shortcut: "p+Shift",
        onclick: async (e) => {
          const descendants = await $selectedResource.get_descendants();
          clearModified(descendants);
          await rootResource.pack_recursively();
          if (!$resourceNodeDataMap[$selected]) {
            $resourceNodeDataMap[$selected] = {};
          }
          $resourceNodeDataMap[$selected].collapsed = false;
          $resourceNodeDataMap[$selected].childrenPromise =
            rootResource.get_children();
          refreshResource();
        },
      },

      {
        text: "Add comment",
        iconUrl: "/icons/comment.svg",
        onclick: async (e) => {
          modifierView = CommentView;
        },
      },

      {
        text: "Search",
        iconUrl: "/icons/identify.svg",
        onclick: async (e) => {
          modifierView = SearchView;
        },
      },

      {
        text: "Show Script",
        iconUrl: "/icons/document.svg",
        onclick: async (e) => {
          bottomLeftPane = ScriptView;
        },
      },

      {
        text: "Settings",
        iconUrl: "/icons/settings.svg",
        onclick: async (e) => {
          modifierView = SettingsView;
        },
      },
    ];
  }

  $: if ($selectedProject) {
    toolbarButtons = [...toolbarButtons, ...projectFeatures];
  }

  $: if ($settings.experimentalFeatures) {
    toolbarButtons = [...toolbarButtons, ...experimentalFeatures];
  }

  function clearModified(descendants) {
    for (const descendant of descendants) {
      if (!$resourceNodeDataMap[descendant["resource_id"]]) {
        $resourceNodeDataMap[descendant["resource_id"]] = {};
      }
      $resourceNodeDataMap[descendant["resource_id"]].lastModified = undefined;
      $resourceNodeDataMap[descendant["resource_id"]].allModified = undefined;
    }
  }
</script>

<Toolbar toolbarButtons="{toolbarButtons}" />
