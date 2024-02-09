<style>
  .icon {
    width: 1em;
    height: 1em;
    display: inline-block;

    background-color: var(--main-fg-color);

    -webkit-mask-size: cover;
    mask-size: cover;
  }
</style>

<script>
  export let url;
  // Allow the parent component to add a class (or several) to the icon
  let extendable_class = "icon " + ($$props.class || "");
</script>

<div
  style:mask-image="{`url(${url})`}"
  style:-webkit-mask-image="{`url(${url})`}"
  class="{extendable_class}"
></div>
