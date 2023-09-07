<style>
  button {
    margin: var(--button-margin, 0, 0, 1em, 0);
    padding: var(--button-padding, (0.5em, 1em, 0.5em, 1em));
    background-color: var(--button-background-color, --main-bg-color);
    color: var(--button-color, --main-fg-color);
    border-color: var(--button-color, --main-fg-color);
    border: var(--button-border, 1px solid);
    border-radius: var(--button-border-radius, 0);
    font-size: smaller;
    overflow: hidden;
    box-shadow: none;
  }

  button:hover,
  button:focus {
    outline: none;
    box-shadow: inset 1px 1px 0 var(--main-fg-color),
      inset -1px -1px 0 var(--main-fg-color);
  }

  button:active {
    box-shadow: inset 2px 2px 0 var(--main-fg-color),
      inset -2px -2px 0 var(--main-fg-color);
  }
</style>

<button {...$$props} {...$$restProps} on:click on:hover>
  <slot />
</button>
