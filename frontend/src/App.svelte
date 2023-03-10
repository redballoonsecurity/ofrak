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
  import AssemblyView from "./AssemblyView.svelte";
  import AttributesView from "./AttributesView.svelte";
  import AudioPlayer from "./AudioPlayer.svelte";
  import ByteclassView from "./ByteclassView.svelte";
  import CarouselSelector from "./CarouselSelector.svelte";
  import EntropyView from "./EntropyView.svelte";
  import HexView from "./HexView.svelte";
  import JumpToOffset from "./JumpToOffset.svelte";
  import LoadingAnimation from "./LoadingAnimation.svelte";
  import MagnitudeView from "./MagnitudeView.svelte";
  import Pane from "./Pane.svelte";
  import ResourceTreeView from "./ResourceTreeView.svelte";
  import Split from "./Split.svelte";
  import StartView from "./StartView.svelte";
  import TextView from "./TextView.svelte";

  import { printConsoleArt } from "./console-art.js";
  import { selected, selectedResource } from "./stores.js";
  import { keyEventToString, shortcuts } from "./keyboard.js";

  import { writable } from "svelte/store";

  printConsoleArt();

  let showRootResource = false,
    displayDataPromise = Promise.resolve([]),
    hexScrollY = writable({}),
    useAssemblyView = false,
    useTextView = false,
    rootResourceLoadPromise = new Promise((resolve) => {}),
    resourceNodeDataMap = {},
    resources = {};
  let carouselSelection, currentResource, rootResource, modifierView;

  let riddleAnswered = JSON.parse(window.localStorage.getItem("riddleSolved"));
  if (riddleAnswered === null || riddleAnswered === undefined) {
    riddleAnswered = false;
  }

  $: if ($selected !== undefined) {
    currentResource = resources[$selected];
    if (currentResource === undefined) {
      console.error("Couldn't get the resource for ID " + $selected);
    } else {
      $selectedResource = currentResource;
      displayDataPromise = currentResource.get_data();
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
    if (
      ["input", "textarea"].includes(e.target?.tagName.toLocaleLowerCase()) ||
      e.target.isContentEditable
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
</script>

<svelte:window on:popstate="{backButton}" on:keyup="{handleShortcut}" />

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
              dataPromise="{displayDataPromise}"
              bind:modifierView="{modifierView}"
              bind:resourceNodeDataMap="{resourceNodeDataMap}"
            />
          {:else}
            <ResourceTreeView
              rootResource="{rootResource}"
              bind:resourceNodeDataMap="{resourceNodeDataMap}"
              bind:modifierView="{modifierView}"
            />
          {/if}
        </Pane>
        <Pane slot="second" paddingVertical="{'1em'}">
          <AttributesView resource="{currentResource}" />
        </Pane>
      </Split>
      <Pane
        slot="second"
        scrollY="{hexScrollY}"
        displayMinimap="{currentResource && !useAssemblyView && !useTextView}"
      >
        {#if useAssemblyView}
          <AssemblyView />
        {:else if useTextView}
          <TextView dataPromise="{displayDataPromise}" />
        {:else}
          <HexView
            dataPromise="{displayDataPromise}"
            resources="{resources}"
            scrollY="{hexScrollY}"
            bind:resourceNodeDataMap="{resourceNodeDataMap}"
          />
        {/if}
        <!-- 
          Named slot must be outside {#if} because of: 
          https://github.com/sveltejs/svelte/issues/5604 
        -->
        <svelte:fragment slot="minimap">
          <JumpToOffset
            dataPromise="{displayDataPromise}"
            scrollY="{hexScrollY}"
          />
          {#if carouselSelection === "Entropy"}
            <EntropyView scrollY="{hexScrollY}" />
          {:else if carouselSelection === "Byteclass"}
            <ByteclassView scrollY="{hexScrollY}" />
          {:else if carouselSelection === "Magnitude"}
            <MagnitudeView scrollY="{hexScrollY}" />
          {/if}
          <div class="carousel">
            <CarouselSelector
              options="{['Magnitude', 'Entropy', 'Byteclass']}"
              bind:selectedString="{carouselSelection}"
            />
          </div>
        </svelte:fragment>
      </Pane>
    </Split>
  {/await}

  {#if riddleAnswered}
    <div class="bottomleft">
      <AudioPlayer />
    </div>
  {/if}
{:else}
  <StartView
    bind:rootResourceLoadPromise="{rootResourceLoadPromise}"
    bind:showRootResource="{showRootResource}"
    bind:resources="{resources}"
    bind:rootResource="{rootResource}"
    bind:resourceNodeDataMap="{resourceNodeDataMap}"
  />
{/if}

<div class="bottomright">
  <p><a href="https://ofrak.com" target="_blank" rel="noreferrer">v2.2.1</a></p>
</div>
