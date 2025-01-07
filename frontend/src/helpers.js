import { settings } from "./stores";
import { get } from "svelte/store";

/***
 * Return the hex string of a single input byte.
 */
export function byteToHex(i) {
  return i.toString(16).padStart(2, "0");
}

/***
 * Return the ASCII character corresponding to the input byte (if applicable).
 * Otherwise, if non-printable, return a string with just a period.
 */
export function hexToChar(hex) {
  const b = parseInt(hex, 16);
  return 31 < b && b < 127 ? String.fromCharCode(b) : ".";
}

/***
 * Split an array into fixed-size chunks.
 */
export function chunkList(l, chunkSize) {
  let result = [];
  for (let i = 0; i < l.length; i += chunkSize) {
    result.push(l.slice(i, i + chunkSize));
  }
  return result;
}

/***
 * Get a Uint8Array (i.e., byte array) from a hex string.
 */
export function hexToByteArray(hex) {
  return Uint8Array.from(
    chunkList(hex, 2).map((hexByte) => parseInt(hexByte, 16))
  );
}

/***
 * Turn an OFRAK import path into a type name without the full dotted path.
 */
export function cleanOfrakType(t) {
  const elements = t.split(".");
  const last = elements[elements.length - 1];
  return last.replace(/AttributesType\[(.*)\]/, "$1");
}

/***
 * Convert an ArrayBuffer to a hex string.
 */
export function buf2hex(buffer, joinchar) {
  return Array.from(new Uint8Array(buffer))
    .map((x) => x.toString(16).padStart(2, "0"))
    .join(joinchar ? joinchar : "");
}

/***
 * Asynchronously sleep for a certain number of milliseconds.
 */
export async function sleep(ms) {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Turn a number of bytes into a text-based file size
 */
export function numBytesToQuantity(bytes) {
  if (bytes < 1024) {
    return `${bytes}B`;
  } else if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(2)}KB`;
  } else if (bytes < 1024 * 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(2)}MB`;
  } else if (bytes < 1024 * 1024 * 1024 * 1024) {
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)}GB`;
  } else {
    // TODO if necessary
    return `${bytes}B`;
  }
}

/***
 * Evaluate an input arithmetic string consisting of (possibly hex) numbers
 * and the given binary operators using the Shunting Yard algorithm
 */
export const calculator = {
  operators: {
    "^": {
      precedence: 4,
      leftAssociative: false,
      operate: (stack) => {
        let y = stack.pop();
        let x = stack.pop();
        stack.push(Math.pow(x, y));
      },
    },
    "*": {
      precedence: 3,
      leftAssociative: true,
      operate: (stack) => {
        let y = stack.pop();
        let x = stack.pop();
        stack.push(x * y);
      },
    },
    "/": {
      precedence: 3,
      leftAssociative: true,
      operate: (stack) => {
        let y = stack.pop();
        let x = stack.pop();
        stack.push(Math.floor(x / y));
      },
    },
    "+": {
      precedence: 2,
      leftAssociative: true,
      operate: (stack) => {
        let y = stack.pop();
        let x = stack.pop();
        stack.push(x + y);
      },
    },
    "-": {
      precedence: 2,
      leftAssociative: true,
      operate: (stack) => {
        let y = stack.pop();
        let x = stack.pop();
        stack.push(x - y);
      },
    },
  },
  calculate: (s) => {
    let stack = [];
    let output = [];

    // Strip spaces
    s = s.replace(/\s+/g, "");

    while (s) {
      // Match numeric literals
      //
      // TODO: Match negative numbers and handle errors from parsing minus
      // operations as negative signs
      const matchNum = s.match(/^(0x[a-fA-F\d]+|\d+)/);
      if (matchNum) {
        // parseInt also parses hex values with an 0x prefix. See:
        // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/parseInt#description
        output.push(parseInt(matchNum[0]));
        s = s.slice(matchNum[0].length);
      }

      // Match operators
      else if (calculator.operators[s[0]]) {
        const parsedOperator = calculator.operators[s[0]];

        if (stack.length == 0) {
          stack.push(s[0]);
          s = s.slice(1);
          continue;
        }

        let lastOperator = stack[stack.length - 1];
        // Pop operators with higher precedence off the stack and perform the
        // operations for each
        if (parsedOperator.leftAssociative) {
          while (
            lastOperator &&
            lastOperator !== "(" &&
            calculator.operators[lastOperator].precedence >=
              parsedOperator.precedence
          ) {
            const operator = calculator.operators[stack.pop()];
            operator.operate(output);
            lastOperator = stack[stack.length - 1];
          }
        } else {
          while (
            lastOperator &&
            lastOperator !== "(" &&
            calculator.operators[lastOperator].precedence >
              parsedOperator.precedence
          ) {
            const operator = calculator.operators[stack.pop()];
            operator.operate(output);
            lastOperator = stack[stack.length - 1];
          }
        }

        stack.push(s[0]);
        s = s.slice(1);
      }

      // Match opening parenthesis
      else if (s[0] === "(") {
        stack.push("(");
        s = s.slice(1);
      }

      // Match closing parenthesis
      else if (s[0] === ")") {
        while (stack[stack.length - 1] !== "(") {
          const operator = calculator.operators[stack.pop()];
          operator.operate(output);
        }
        stack.pop();
        s = s.slice(1);
      }

      // Nothing matched!
      else {
        throw new Error("Invalid input that does not parse as an expression!");
      }
    }

    while (stack.length > 0) {
      const operator = calculator.operators[stack.pop()];
      operator.operate(output);
    }

    return output[0];
  },
};

/***
 * Title case a variable name, whether in camel case or snake case.
 */
export function splitAndCapitalize(name) {
  return name
    .split(/_|(?=[A-Z])/)
    .map((name) => name.charAt(0).toUpperCase() + name.slice(1))
    .join(" ");
}

/***
 *
 */
export function saveSettings() {
  window.localStorage.setItem("settings", JSON.stringify(get(settings)));
}

export function getTextSizeInPixels(element, text) {
  const c = document.createElement("canvas");
  const ctx = c.getContext("2d");
  ctx.font = `${getComputedStyle(element).getPropertyValue(
    "font-size"
  )} ${getComputedStyle(element).getPropertyValue("font-family")}`;
  return ctx.measureText(text);
}
