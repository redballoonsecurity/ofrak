<style>
  .hbox {
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: flex-start;
    width: 100%;
    height: 100%;
    max-height: 100%;
  }
  .manager {
    width: 100%;
  }
  .title {
    text-transform: uppercase;
    font-weight: bold;
    color: inherit;
    font-size: xxx-large;
    line-height: 1;
    margin: 0;
    max-width: 100%;
    max-height: 100%;
    text-align: center;
  }
  .sub-title {
    padding-bottom: 0.5em;
    text-align: center;
    font-size: xx-large;
    font-weight: bold;
    text-transform: uppercase;
  }

  .hbox2 {
    width: 100%;
    padding: 2em;
    overflow-y: hidden;
  }

  .content {
    font-size: x-large;
    display: flex;
    flex-direction: column;
    width: 100%;
    overflow: auto;
  }

  .hint {
    font-size: medium;
    height: 1em;
    margin-bottom: 1em;
  }
</style>

<script>
  import Pane from "../Pane.svelte";
  import Split from "../Split.svelte";
  import ProjectManagerFocusableLabel from "./ProjectManagerFocusableLabel.svelte";
  import ProjectManagerOptions from "./ProjectManagerOptions.svelte";
  import { selectedProject, settings, selected } from "../stores";
  import { remote_model_to_resource } from "../ofrak/remote_resource";
  import ProjectManagerToolbar from "./ProjectManagerToolbar.svelte";
  import ProjectManagerAddBinaryToProject from "./ProjectManagerAddBinaryToProject.svelte";
  import ProjectManagerAddScriptToProject from "./ProjectManagerAddScriptToProject.svelte";
  import ProjectManagerMainOptions from "./ProjectManagerMainOptions.svelte";
  import { onMount } from "svelte";
  import ProjectManagerCheckbox from "./ProjectManagerCheckbox.svelte";
  import ProjectManagerScriptOptions from "./ProjectManagerScriptOptions.svelte";

  let focus,
    selectedBinaryName,
    focusBinary,
    focusScript,
    forceRefreshProject = {},
    scriptCheckboxHoverInfo = {};

  let binariesForProject = [];
  for (let binaryName in $selectedProject.binaries) {
    if ($selectedProject.binaries.hasOwnProperty(binaryName)) {
      binariesForProject.push(binaryName);
    }
  }

  export let resources,
    rootResourceLoadPromise,
    rootResource,
    showRootResource,
    showProjectManager;

  async function openProject() {
    let rootModel = await fetch(`${$settings.backendUrl}/open_project`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        id: $selectedProject.session_id,
        binary: selectedBinaryName,
        script: $selectedProject.binaries[selectedBinaryName].init_script,
      }),
    }).then((r) => r.json());
    rootResource = remote_model_to_resource(rootModel, resources);
    $selected = rootModel.id;
    showProjectManager = false;
    showRootResource = true;
  }

  onMount(async () => {
    focus = {
      object: ProjectManagerMainOptions,
      args: {},
    };
  });
  $: rootResourceLoadPromise = openProject;
  $: {
    focus = {
      object: ProjectManagerScriptOptions,
      args: {
        name: focusBinary,
      },
    };
    selectedBinaryName = focusBinary;
    focusBinary = undefined;
  }
  $: {
    focus = {
      object: ProjectManagerScriptOptions,
      args: {
        name: focusScript,
      },
    };
    focusScript = undefined;
  }
</script>

<div class="title">OFRAK Project Manager</div>
<div class="hbox">
  <ProjectManagerToolbar
    bind:focus="{focus}"
    openProject="{openProject}"
    bind:showProjectManager="{showProjectManager}"
    bind:forceRefreshProject="{forceRefreshProject}"
  />
  <div class="manager">
    <Split vertical="{true}" percentOfFirstSplit="{70}">
      <Split percentOfFirstSplit="{50}" slot="first">
        <Pane slot="first">
          <div class="sub-title">
            <ProjectManagerFocusableLabel
              bind:focus="{focus}"
              label="Binaries"
              newFocus="{ProjectManagerAddBinaryToProject}"
            />
          </div>
          <div class="hbox2">
            <div class="content">
              {#each binariesForProject as binaryName}
                <div class="element">
                  <ProjectManagerCheckbox
                    ownValue="{binaryName}"
                    checkbox="{false}"
                    bind:focus="{focusBinary}"
                  />
                </div>
              {/each}
            </div>
          </div>
        </Pane>
        <Pane slot="second">
          <div class="sub-title">
            <ProjectManagerFocusableLabel
              bind:focus="{focus}"
              label="Scripts"
              newFocus="{ProjectManagerAddScriptToProject}"
            />
          </div>
          <div class="hbox2">
            <div class="content">
              <div class="element hint">
                {#if scriptCheckboxHoverInfo.onInclusive}
                  <p>
                    Script is {#if !scriptCheckboxHoverInfo.inclusiveChecked}
                      not
                    {/if} compatible with this binary
                  </p>
                {:else if scriptCheckboxHoverInfo.onExclusive}
                  <p>
                    Script is {#if !scriptCheckboxHoverInfo.exclusiveChecked}
                      not
                    {/if} the one used to launch this binary
                  </p>
                {/if}
              </div>
              {#each $selectedProject.scripts as script}
                <div class="element">
                  {#if selectedBinaryName}
                    {#key forceRefreshProject}
                      <ProjectManagerCheckbox
                        ownValue="{script['name']}"
                        inclusiveSelectionGroup="{$selectedProject.binaries[
                          selectedBinaryName
                        ].associated_scripts}"
                        bind:exclusiveSelectionValue="{$selectedProject
                          .binaries[selectedBinaryName].init_script}"
                        bind:focus="{focusScript}"
                        bind:mouseoverInfo="{scriptCheckboxHoverInfo}"
                      />
                    {/key}
                  {:else}
                    <ProjectManagerCheckbox
                      ownValue="{script['name']}"
                      bind:focus="{focusScript}"
                    />
                  {/if}
                </div>
              {/each}
            </div>
          </div>
        </Pane>
      </Split>
      <Pane slot="second" paddingVertical="{'1em'}">
        <ProjectManagerOptions focus="{focus}" />
      </Pane>
    </Split>
  </div>
</div>
