<script>
  let hovering;

  function enter() {
    hovering = true;
  }

  function leave() {
    hovering = false;
  }
</script>

<span on:mouseenter="{enter}" on:mouseleave="{leave}">
  <slot hovering="{hovering}" />
</span>
