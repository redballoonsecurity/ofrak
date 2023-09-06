<style>
    button {
        padding-top: 0.5em;
        padding-bottom: 0.5em;
        padding-left: 1em;
        padding-right: 1em;
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
    <slot/>
</button>