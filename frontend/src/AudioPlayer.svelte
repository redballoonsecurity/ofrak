<style>
  button {
    background: none;
    border: none;
    margin-left: 0.5em;
    margin-right: 0.5em;
    box-shadow: none;
    user-select: none;
    font-size: initial;
  }
</style>

<script>
  let audioPlayer;

  /*
    Uses royalty free music from Nihilore:
    http://www.nihilore.com/synthwave
    http://www.nihilore.com/license
  */
  const sources = [
    "/sounds/Bush+Week.mp3",
    "/sounds/Glimmer.mp3",
    "/sounds/Motion+Blur.mp3",
    "/sounds/Panthalassa.mp3",
    "/sounds/Dream+Sunlight.mp3",
  ];
  let currentSound = Math.floor(Math.random() * sources.length);

  let autoplay = JSON.parse(window.localStorage.getItem("audioAutoplay"));
  if (autoplay === null) {
    autoplay = true;
  }

  function playAudio(player) {
    player.volume = 0.6;
    if (autoplay) {
      // This is more reliable than the built-in `autoplay` attribute for the
      // <audio> tag
      player.play();
      autoplay = false;
    }
  }
  $: if (audioPlayer !== undefined) {
    playAudio(audioPlayer);
  }
</script>

<audio
  src="{sources[currentSound]}"
  bind:this="{audioPlayer}"
  on:ended="{(_) => {
    currentSound = (currentSound + 1) % sources.length;
    autoplay = true;
    // TODO: Figure out why this needs to be in a timeout
    setTimeout(() => playAudio(audioPlayer), 1);
  }}"></audio>
<button
  on:click="{() => {
    if (audioPlayer !== undefined) {
      if (audioPlayer.paused) {
        audioPlayer.play();
      } else {
        audioPlayer.pause();
      }
      audioPlayer = audioPlayer;

      window.localStorage.setItem(
        'audioAutoplay',
        JSON.stringify(!audioPlayer.paused)
      );
    }
  }}"
>
  {#if !audioPlayer?.paused}
    &#9612;&#9612;
  {:else}
    &#x25B6;&#xFE0E;
  {/if}
</button>
