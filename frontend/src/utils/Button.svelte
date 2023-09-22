<style>
  button {
    display: flow-root;
    width: var(--button-flex-grow, auto);
    height: var(--button-flex-grow, auto);
    flex-grow: var(--button-flex-grow, inherit);
    margin: var(--button-margin, 0.5em);
    padding: var(--button-padding, 0.5em 1em);
    background-color: var(--button-background-color, var(--main-bg-color));
    color: var(--button-color, var(--main-fg-color));
    border-color: var(--button-color, var(--main-fg-color));
    border: var(--button-border, 1px solid);
    border-radius: var(--button-border-radius, 0);
    overflow: hidden;
    box-shadow: none;
    color: inherit;
  }

  button:hover,
  button:focus {
    outline: none;
    box-shadow: inset 1px 1px 0, inset -1px -1px 0;
  }

  button:active {
    box-shadow: inset 2px 2px 0, inset -2px -2px 0;
  }

  button:disabled {
    opacity: 0.45;
    cursor: not-allowed;
  }
</style>

<button {...$$props} {...$$restProps} on:click on:hover>
  <slot />
</button>
