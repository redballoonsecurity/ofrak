<style>
  div {
    width: 100%;
    margin: 2em 0;
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    align-items: center;
    justify-content: center;
  }

  hr {
    flex-grow: 1;
    border: none;
    color: inherit;
    border-bottom: 1px solid currentColor;
  }

  span {
    padding: 0 2ch;
  }
</style>

<script>
  export let color;
</script>

<div>
  <hr style:color="{color}" />
  <span><slot /></span>
  <hr style:color="{color}" />
</div>
