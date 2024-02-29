<style>
  * {
    box-sizing: border-box;
  }

  .carousel {
    margin-top: 1em;
  }

  .bottomleft {
    position: absolute;
    bottom: 0.5em;
    left: 0.5em;
    color: var(--main-fg-color);
    z-index: 9999999;
  }

  .bottomright {
    position: absolute;
    bottom: -0.75em;
    right: 0.5em;
    color: var(--main-fg-color);
    z-index: 9999999;
  }

  a {
    color: inherit;
  }
</style>

<script>
  import AssemblyView from "./views/AssemblyView.svelte";
  import AttributesView from "./views/AttributesView.svelte";
  import AudioPlayer from "./utils/AudioPlayer.svelte";
  import Gamepad from "./utils/Gamepad.svelte";
  import HexView from "./hex/HexView.svelte";
  import LoadingAnimation from "./utils/LoadingAnimation.svelte";
  import Pane from "./utils/Pane.svelte";
  import ResourceTreeView from "./resource/ResourceTreeView.svelte";
  import Split from "./utils/Split.svelte";
  import StartView from "./views/StartView.svelte";
  import TextView from "./views/TextView.svelte";
  import ProjectManagerView from "./project/ProjectManagerView.svelte";

  import { printConsoleArt } from "./console-art.js";
  import {
    selected,
    selectedResource,
    settings,
    dataLength,
  } from "./stores.js";
  import { keyEventToString, shortcuts } from "./keyboard.js";

  import { writable } from "svelte/store";

  printConsoleArt();

  let showRootResource = false,
    showProjectManager = false,
    dataLenPromise = Promise.resolve([]),
    hexScrollY = writable({}),
    useAssemblyView = false,
    useTextView = false,
    rootResourceLoadPromise = new Promise((resolve) => {}),
    resources = {};
  let currentResource, rootResource, modifierView, bottomLeftPane;

  // TODO: Move to settings
  let riddleAnswered = JSON.parse(window.localStorage.getItem("riddleSolved"));
  if (riddleAnswered === null || riddleAnswered === undefined) {
    riddleAnswered = false;
  }

  $: dataLenPromise.then((r) => {
    $dataLength = r;
  });

  $: if ($selected !== undefined) {
    currentResource = resources[$selected];
    if (currentResource === undefined) {
      console.error("Couldn't get the resource for ID " + $selected);
    } else {
      $selectedResource = currentResource;
      dataLenPromise = currentResource.get_data_length();
      useAssemblyView = [
        "ofrak.core.complex_block.ComplexBlock",
        "ofrak.core.basic_block.BasicBlock",
        "ofrak.core.instruction.Instruction",
        "ofrak.core.data.DataWord",
      ].some((tag) => currentResource.has_tag(tag));
      useTextView = ["ofrak.core.binary.GenericText"].some((tag) =>
        currentResource.has_tag(tag)
      );
      $hexScrollY.top = 0;
      document.title = "OFRAK App – " + currentResource.get_caption();
    }
    if ($selected !== window.location.hash.slice(1)) {
      window.history.pushState(null, "", `#${$selected}`);
    }
  }

  function backButton() {
    if (
      window.location.hash &&
      resources &&
      resources[window.location.hash.slice(1)]
    ) {
      $selected = window.location.hash.slice(1);
    }
  }

  function handleShortcut(e) {
    // Don't handle keypresses from within text inputs.
    // Disable shortcuts in views with text inputs, otherwise misclicking outside of a text area may
    // cause users to accidentally run shortcuts.
    if (
      ["input", "textarea"].includes(e.target?.tagName.toLocaleLowerCase()) ||
      e.target.isContentEditable ||
      modifierView
    ) {
      return;
    }
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();
    const keyString = keyEventToString(e);
    const callback = shortcuts[keyString];
    if (callback) {
      callback();
    }
  }

  window.riddle = {
    ask: () => {
      console.log(`Answer the following riddle for a special Easter egg surprise:

I have keys, but no locks.
I have a space, but no room.
You can enter, but you can't exit, though you can escape.

What am I?

Answer by running riddle.answer('your answer here') from the console.`);
    },
    answer: (s) => {
      if (s.toLocaleLowerCase().endsWith(atob("a2V5Ym9hcmQ="))) {
        riddleAnswered = true;
        window.localStorage.setItem(
          "riddleSolved",
          JSON.stringify(riddleAnswered)
        );
      }
    },
  };
  window.riddle.ask();

  // Use colors from settings
  const docstyle = document.documentElement.style;
  $: docstyle.setProperty("--main-bg-color", $settings.background);
  $: docstyle.setProperty("--main-fg-color", $settings.foreground);
  $: docstyle.setProperty("--selected-bg-color", $settings.selected);
  $: docstyle.setProperty("--highlight-color", $settings.highlight);
  $: docstyle.setProperty("--comment-color", $settings.comment);
  $: docstyle.setProperty("--accent-text-color", $settings.accentText);
  $: docstyle.setProperty("--last-modified-color", $settings.lastModified);
  $: docstyle.setProperty("--all-modified-color", $settings.allModified);
</script>

<svelte:window on:popstate="{backButton}" on:keyup="{handleShortcut}" />
<Gamepad />

{#if showRootResource}
  {#await rootResourceLoadPromise}
    <LoadingAnimation />
  {:then _}
    <Split>
      <Split slot="first" vertical="{true}" percentOfFirstSplit="{66.666}">
        <Pane slot="first">
          {#if modifierView}
            <svelte:component
              this="{modifierView}"
              dataLenPromise="{dataLenPromise}"
              bind:modifierView="{modifierView}"
            />
          {:else}
            <ResourceTreeView
              rootResource="{rootResource}"
              bind:bottomLeftPane="{bottomLeftPane}"
              bind:modifierView="{modifierView}"
              bind:showProjectManager="{showProjectManager}"
              bind:showRootResource="{showRootResource}"
            />
          {/if}
        </Pane>
        <Pane slot="second" paddingVertical="{'1em'}">
          {#if bottomLeftPane}
            <svelte:component
              this="{bottomLeftPane}"
              bind:bottomLeftPane="{bottomLeftPane}"
            />
          {:else}
            <AttributesView resource="{currentResource}" />
          {/if}
        </Pane>
      </Split>
      <Pane slot="second" scrollY="{hexScrollY}">
        {#if useAssemblyView}
          <AssemblyView />
        {:else if useTextView}
          <TextView />
        {:else}
          <HexView
            dataLenPromise="{dataLenPromise}"
            resources="{resources}"
            scrollY="{hexScrollY}"
          />
        {/if}
        <!-- 
          Named slot must be outside {#if} because of: 
          https://github.com/sveltejs/svelte/issues/5604 
        -->
      </Pane>
    </Split>
  {/await}

  {#if riddleAnswered}
    <div class="bottomleft">
      <AudioPlayer />
    </div>
  {/if}
{:else if showProjectManager}
  <ProjectManagerView
    bind:rootResourceLoadPromise="{rootResourceLoadPromise}"
    bind:rootResource="{rootResource}"
    bind:resources="{resources}"
    bind:showRootResource="{showRootResource}"
    bind:showProjectManager="{showProjectManager}"
  />
{:else}
  <StartView
    bind:rootResourceLoadPromise="{rootResourceLoadPromise}"
    bind:showRootResource="{showRootResource}"
    bind:showProjectManager="{showProjectManager}"
    bind:resources="{resources}"
    bind:rootResource="{rootResource}"
  />
{/if}

<div class="bottomright">
  <p>
    <a href="https://ofrak.com" target="_blank" rel="noreferrer">v3.2.0</a>
  </p>
</div>
