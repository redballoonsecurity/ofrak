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
    "https://static1.squarespace.com/static/57e83f709de4bbd550a2fdba/58e6e631579fb3bb25ed2822/606d59d50726d2518e6c8725/1617779204095/Dream+Sunlight.mp3",
    "https://static1.squarespace.com/static/57e83f709de4bbd550a2fdba/58e6e631579fb3bb25ed2822/5b9332214d7a9cece566be20/1536373390381/Glimmer.mp3",
    "https://static1.squarespace.com/static/57e83f709de4bbd550a2fdba/58e6e631579fb3bb25ed2822/6323fd85ebe8f81bc36cd975/1663303114116/Eternal+Light.mp3",
    "https://static1.squarespace.com/static/57e83f709de4bbd550a2fdba/58e6e631579fb3bb25ed2822/5a7e6ee1ec212d8118ae4857/1518235615625/Panthalassa.mp3",
    "https://static1.squarespace.com/static/57e83f709de4bbd550a2fdba/58e6e631579fb3bb25ed2822/5ab591b7562fa77d176c3f72/1521848881258/Motion+Blur.mp3",
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
