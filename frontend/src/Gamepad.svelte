<script>
  import { onMount } from "svelte";

  import { shortcuts } from "./keyboard.js";

  let animationLoop,
    gamepad,
    buttons = {
      0: {
        name: "Up",
        shortcut: "arrowup",
      },
      1: {
        name: "Down",
        shortcut: "arrowdown",
      },
      2: {
        name: "Right",
        shortcut: "arrowright",
      },
      3: {
        name: "Left",
        shortcut: "arrowleft",
      },
      4: {
        name: "Square",
        shortcut: "p",
      },
      5: {
        name: "Triangle",
        shortcut: "u",
      },
      6: {
        name: "X",
        shortcut: "i",
      },
      7: {
        name: "O",
        shortcut: "a",
      },
      8: {
        name: "Select",
      },
      9: {
        name: "Start",
        shortcut: "n",
      },
    };

  function isValidGamepad(gamepad) {
    // TODO: Refine selection criteria to handle non-DDR gamepads
    return gamepad && gamepad.axes.length == 0 && gamepad.buttons.length >= 10;
  }

  function loop() {
    if (!gamepad || !gamepad.connected) {
      disconnected();
      return;
    }

    gamepad.buttons.forEach((b, i) => {
      if (!buttons[i]) {
        return;
      }
      // On button release, if the button corresponds to an OFRAK shortcut and
      // that shortcut is found, trigger the shortcut
      if (buttons[i].pressed && !b.pressed) {
        buttons[i].shortcut &&
          shortcuts[buttons[i].shortcut] &&
          shortcuts[buttons[i].shortcut]();
      }
      buttons[i].pressed = b.pressed;
    });

    animationLoop = requestAnimationFrame(loop);
  }

  function connected(e) {
    let _gamepad = e.gamepad;
    if (isValidGamepad(_gamepad)) {
      gamepad = _gamepad;
    } else {
      return;
    }
    animationLoop = requestAnimationFrame(loop);
  }

  function disconnected() {
    gamepad = undefined;
    if (animationLoop) {
      cancelAnimationFrame(animationLoop);
    }
  }

  onMount(() => {
    for (const _gamepad of navigator.getGamepads()) {
      if (isValidGamepad(_gamepad)) {
        gamepad = _gamepad;
        break;
      }
    }

    animationLoop = requestAnimationFrame(loop);
  });
</script>

<svelte:window
  on:gamepadconnected="{connected}"
  on:gamepaddisconnected="{disconnected}"
/>
