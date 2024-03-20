<style>
  .boxed {
    border: 2px solid var(--main-fg-color);
    padding: 2em;
    margin: 1em 0 2em 0;
  }

  .buttonbar {
    top: 0;
    left: 0;
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    align-items: start;
    justify-content: start;
  }
</style>

<script>
  import Button from "../Button.svelte";
  import Icon from "../Icon.svelte";

  export let node, nodeName, element, baseForm;

  const addSubElementToDict = () => {
    element = [...element, [null, null]];
  };

  function removeSubElementFromDict(idx) {
    element = element.toSpliced(idx, 1);
  }
</script>

<div class="buttonbar">
  <Button --button-padding="0.5em 1em 0em 1em" on:click="{addSubElementToDict}">
    <Icon url="/icons/plus.svg" />
  </Button>
</div>
{#each element as [subElementKey, subElementValue], index}
  <div class="boxed">
    <div class="buttonbar">
      <Button
        --button-padding="0.5em 1em 0em 1em"
        on:click="{(e) => removeSubElementFromDict(index)}"
      >
        <Icon url="/icons/error.svg" />
      </Button>
    </div>
    <p>Key</p>
    <svelte:component
      this="{baseForm}"
      node="{node.args[0]}"
      nodeName="{nodeName}"
      bind:element="{subElementKey}"
    />
    <p>Value</p>
    <svelte:component
      this="{baseForm}"
      node="{node.args[1]}"
      bind:element="{subElementValue}"
    />
  </div>
{/each}
