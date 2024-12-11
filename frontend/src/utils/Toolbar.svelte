<style>
  .vbox {
    display: flex;
    flex-direction: column;
    flex-wrap: nowrap;
    justify-content: flex-start;
    align-items: stretch;
  }
</style>

<script>
  import Icon from "./Icon.svelte";
  import Button from "./Button.svelte";
  import { shortcuts } from "../keyboard.js";

  export let toolbarButtons;

  /***
   * Show the loading spinner while an async onclick function does its thing.
   */
  function wrapOnCick(button) {
    return async (e) => {
      const oldIcon = button.iconUrl;
      button.iconUrl = "/icons/loading.svg";
      toolbarButtons = toolbarButtons;
      await button
        .onclick(e)
        .then((_) => {
          button.iconUrl = oldIcon;
          toolbarButtons = toolbarButtons;
        })
        .catch((e) => {
          button.iconUrl = "/icons/error.svg";
          toolbarButtons = toolbarButtons;
          try {
            let errorObject = JSON.parse(e.message);
            alert(`${errorObject.type}: ${errorObject.message}`);
          } catch {
            alert(e);
          }
          console.error(e);
        });
    };
  }

  $: Array.from(toolbarButtons).forEach((button) => {
    if (!button.shortcut) {
      return;
    }
    shortcuts[button.shortcut] = wrapOnCick(button);
  });
</script>

<div class="vbox">
  {#each toolbarButtons as button}
    <Button
      on:click="{wrapOnCick(button)}"
      title="{button.text +
        (button.shortcut
          ? ' (Shortcut key: ' +
            button.shortcut.split('+').reverse().join(' + ') +
            ')'
          : '')}"
      disabled="{button.disabled && button.disabled()}"
    >
      {#if button.iconUrl}
        <Icon url="{button.iconUrl}" />
      {/if}
      {button.text}
    </Button>
  {/each}
</div>
