import { selectedProject, settings } from "../stores";

const defaultSourceBody = [
  '#include "aes_inject.h"',
  '#include "thumb_defines.h"\n',
  "",
  "#ifdef USE_THUMB",
  '__attribute__((target("thumb")))',
  "#else",
  '__attribute__((target("arm")))',
  "#endif",
  "int encrypt(unsigned char *plaintext, int plaintext_len,",
  "            unsigned char *key,",
  "            unsigned char *iv,",
  "            unsigned char *ciphertext)",
  "{",
  "    EVP_CIPHER_CTX *ctx;",
  "",
  "    int len;",
  "    int ciphertext_len;",
  "",
  "    /* Create and initialise the context */",
  "    if(!(ctx = EVP_CIPHER_CTX_new()))",
  "        handleErrors();",
  "",
  "    /* Initialise the encryption operation. */",
  "    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))",
  "        handleErrors();",
  "",
  "    /*",
  "     * Provide the message to be encrypted, and obtain the encrypted output.",
  "     * EVP_EncryptUpdate can be called multiple times if necessary",
  "     */",
  "    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))",
  "        handleErrors();",
  "    ciphertext_len = len;",
  "",
  "    /*",
  "     * Finalise the encryption. Further ciphertext bytes may be written at",
  "     * this stage.",
  "     */",
  "    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))",
  "        handleErrors();",
  "    ciphertext_len += len;",
  "",
  "    /* Clean up */",
  "    EVP_CIPHER_CTX_free(ctx);",
  "",
  "    return ciphertext_len;",
];

const staticName = "Example_Patch";

export function fakePatchInfo() {
  return {
    name: staticName,
    sourceInfos: [
      { name: "file1.c", body: defaultSourceBody, originalName: "file1.c" },
      { name: "file2.c", body: defaultSourceBody, originalName: "file2.c" },
      { name: "file3.h", body: defaultSourceBody, originalName: "file3.h" },
    ],
    objectInfosValid: true,
    objectInfos: [
      {
        name: "file1.c",
        segments: [
          {
            name: ".text",
            size: 0x100,
            permissions: "rx",
            include: true,
            allocatedVaddr: null,
            unit: "file1.c.o",
          },
          {
            name: ".data",
            size: 0x100,
            permissions: "rw",
            include: true,
            allocatedVaddr: null,
            unit: "file1.c.o",
          },
          {
            name: ".rodata",
            size: 0x100,
            permissions: "r",
            include: false,
            allocatedVaddr: null,
            unit: "file1.c.o",
          },
        ],
        strongSymbols: ["foo"],
        unresolvedSymbols: ["printf", "bar", "boogeyman"],
      },
      {
        name: "file2.c",
        segments: [
          {
            name: ".text",
            size: 0x100,
            permissions: "rx",
            include: true,
            allocatedVaddr: null,
            unit: "file2.c.o",
          },
        ],
        strongSymbols: ["bar"],
        unresolvedSymbols: [],
      },
    ],
    targetInfo: {
      symbols: ["printf", "sprintf", "malloc", "calloc", "kalloc"],
    },
    targetInfoValid: true,
    userInputs: {
      symbols: [["example", 0xfeed]],
      toolchain: undefined,
      toolchainConfig: undefined,
    },
    symbolRefMap: null,
  };
}

export async function fakeFetchObjectInfos(
  patchName,
  toolchain,
  toolchainConfig
) {
  let r = await fetch(
    `${$settings.backendUrl}/get_object_infos?patch_name=${patchName}`,
    {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        toolchain: toolchain,
        toolchainConfig: toolchainConfig,
      }),
    }
  );
  if (!r.ok) {
    throw Error(JSON.parse(await r.json()));
  }
  return await r.json();
}

export async function _fakeFetchObjectInfos() {
  return [
    {
      name: "file1.c",
      segments: [
        {
          name: ".text",
          size: 0x100,
          permissions: "rx",
          include: true,
          allocatedVaddr: null,
        },
        {
          name: ".data",
          size: 0x100,
          permissions: "rw",
          include: true,
          allocatedVaddr: null,
        },
        {
          name: ".rodata",
          size: 0x100,
          permissions: "r",
          include: false,
          allocatedVaddr: null,
        },
      ],
      strongSymbols: ["foo"],
      unresolvedSymbols: ["printf", "bar", "boogeyman"],
    },
    {
      name: "file2.c",
      segments: [
        {
          name: ".text",
          size: 0x100,
          permissions: "rx",
          include: true,
          allocatedVaddr: null,
        },
      ],
      strongSymbols: ["bar"],
      unresolvedSymbols: [],
    },
  ];
}

export async function fakeFetchTargetInfo() {
  return {
    symbols: ["printf", "sprintf", "malloc", "calloc", "kalloc"],
  };
}
