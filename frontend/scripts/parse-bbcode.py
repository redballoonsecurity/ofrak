"""
Parse BBCode with ASCII art and turn it into a well-formatted `console.log` function call that
can be pasted into a JavaScript source file.

Used for adding colorized output from https://asciiart.club/ to source files. For best results,
generate ASCII art with:

- Charset: 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ !"#$&'()*+,-./:;=?@^_{|}~
- Sharpness: 100%
- Colorized: 100%
- Colors: white on black
- Size: 80 x 36
"""

import argparse

from parsy import forward_declaration, generate, regex, seq, string


BBCODE = """
[color=#808080]                         [/color][color=#848484]_[/color][color=#969696],[/color][color=#aaaaaa]w[/color][color=#b7b7b7]w[/color][color=#bdbdbd]w[/color][color=#bdbdbd]**xxw[/color][color=#b1b1b1]w[/color][color=#a5a5a5];[/color][color=#979797]_[/color][color=#888888]_[/color]
[color=#808080]                      [/color][color=#a2a2a2],[/color][color=#c2c2c2]*[/color][color=#c3c3c3]M[/color][color=#b5b5b5]T[/color][color=#a09e9e].   [/color][color=#b4aba7]z[/color][color=#b6aaa6]HH*[/color][color=#beb3af]*[/color][color=#bfb3ae]w[/color][color=#baafac]w[/color][color=#b9b2b0]([/color][color=#bcb8b7]?[/color][color=#bfbebe]T[/color][color=#bfbfbf]M#[/color][color=#bcbcbc]w[/color][color=#b1b1b1]w[/color][color=#a1a1a1],[/color][color=#959595]_[/color][color=#878787]_[/color]
[color=#808080]                    [/color][color=#bebebe]w[/color][color=#cecece]M[/color][color=#9e9d9d].[/color][color=#a3948f],[/color][color=#cca297]*[/color][color=#eea08c]@[/color][color=#fd9c83]D[/color][color=#e3917b]R [/color][color=#e7896b]@[/color][color=#ff8d69]D[/color][color=#fe8b66]DDD[/color][color=#ea8c6f]@[/color][color=#d98c73]g[/color][color=#d6927d]w[/color][color=#d69f8d]{[/color][color=#d7aa9b]T[/color][color=#d2b0a5]T[/color][color=#e4c1b6]$[/color][color=#d4bdb6]N[/color][color=#bbb0ac]*[/color][color=#bdb0ac]wwj[/color][color=#adadad]T?[/color][color=#bebdbd]f[/color][color=#bdbdbd]MMK**w[/color][color=#b7b7b7]w[/color][color=#afafaf]w[/color][color=#aaaaaa]u[/color][color=#9e9e9e],[/color][color=#959595]_[/color][color=#898989]_[/color]
[color=#808080]                  [/color][color=#b3b3b3]a[/color][color=#d4d4d4]M [/color][color=#b69389]/[/color][color=#f19076]R[/color][color=#ff7b59]D[/color][color=#ff7450]DDD  D@@@@@@@@@D@@[/color][color=#fd8863]D[/color][color=#ff9371]D[/color][color=#da9e8b]D[/color][color=#f1ac96]0 [/color][color=#e8b8ab]4[/color][color=#f9b5a3]@[/color][color=#f5bcae]N[/color][color=#ecbaad]M[/color][color=#deb4a8]N[/color][color=#d6afa4]p[/color][color=#ac9993]u  [/color][color=#b9ada9]y[/color][color=#baafac]w[/color][color=#bcb3b0]zjT[/color][color=#bbb9b9]?[/color][color=#bfbebe]f[/color][color=#bebebe]MKw[/color][color=#b3b3b3]w[/color][color=#969696]_[/color]
[color=#808080]                 [/color][color=#d7d7d7]4[/color][color=#afafaf]^ [/color][color=#ce684e]j[/color][color=#e95731]j[/color][color=#fa6f4a]K[/color][color=#f67654]R[/color][color=#b87c6b]^[/color][color=#d48066]U[/color][color=#ad8072],[/color][color=#9e8178],[/color][color=#c9846d]a[/color][color=#ff855f]@[/color][color=#ff855f]@D[/color][color=#f08563]R[/color][color=#c4836e]"[/color][color=#c7836e]|[/color][color=#ff855f]D[/color][color=#fd8560]R@@@@@@@[/color][color=#f78561]@[/color][color=#dd8568]D[/color][color=#bb8472]+[/color][color=#9a8179]_ [/color][color=#f17656]R[/color][color=#ff7551]D[/color][color=#fe8160]D [/color][color=#ba8573]|[/color][color=#f1997d]@[/color][color=#fda98e]D[/color][color=#ffb098]D[/color][color=#d49a88]w[/color][color=#b78e80]|[/color][color=#af8f85];[/color][color=#c1a49a]j[/color][color=#ffd9cd]N[/color][color=#fbdcd3]N[/color][color=#f0d6ce]N[/color][color=#dec7c1]N[/color][color=#c8b7b2]w[/color][color=#b8aeaa]u[/color][color=#b5b1af]J[/color][color=#c0c0c0]?[/color][color=#c8c8c8]N[/color][color=#ababab]u[/color]
[color=#808080]                [/color][color=#dfdfdf]0[/color][color=#a1a0a0]'[/color][color=#ae6f5c]-[/color][color=#a67262]_ [/color][color=#ad7a6d]' [/color][color=#93807a]_[/color][color=#d4856b]{[/color][color=#ff855f]@[/color][color=#ff855f]@@@D[/color][color=#f68561]R[/color][color=#d3846b]D[/color][color=#a28277],[/color][color=#f38663]@[/color][color=#d98469]R  [/color][color=#ec8564]0[/color][color=#ff855f]@[/color][color=#ff855f]@@@@@@D[/color][color=#ec8665]@[/color][color=#bb8472]/[/color][color=#c7846f]w[/color][color=#9e8077]_[/color][color=#b77b6c]^[/color][color=#a97f72]_[/color][color=#a58276]-[/color][color=#eb8565]4[/color][color=#ff855f]@[/color][color=#ff855f]@@@@@@[/color][color=#f48562]R[/color][color=#e48567]R[/color][color=#d98970]R[/color][color=#d7927c]T[/color][color=#d0a192]T[/color][color=#d5ada0]T[/color][color=#d3afa3]T[/color][color=#d7c3bc]j[/color][color=#c3b3ae]w[/color][color=#a3a2a1]^[/color][color=#e0e0e0]#[/color]
[color=#808080]               [/color][color=#d0d0d0]4[/color][color=#aeaeae]H[/color][color=#b46d57]|[/color][color=#c5674a]H^[/color][color=#f9805a]R[/color][color=#f88661]@[/color][color=#fc8660]@[/color][color=#ff855f]DD@@D@@[/color][color=#e08467]@[/color][color=#d7846a]@[/color][color=#c2846f]^[/color][color=#b7ada9]y   [/color][color=#f28663]R[/color][color=#fe855f]@[/color][color=#ff855f]@@@@[/color][color=#ee8463]P[/color][color=#b08273]^ [/color][color=#bb8370]j[/color][color=#fc8560]@[/color][color=#e08467]@[/color][color=#d5856b]y[/color][color=#d3866c]y@[/color][color=#ed8564]@[/color][color=#ff855f]@[/color][color=#fe845e]D[/color][color=#fb7f58]R[/color][color=#f17954]R[/color][color=#d27d63]T[/color][color=#d67455]T[/color][color=#e36842]R[/color][color=#c66c50]H[/color][color=#ae6f5c]^[/color][color=#b0725f]'[/color][color=#b17c6a],[/color][color=#b0897b];[/color][color=#ae9185]u[/color][color=#ac988e]u[/color][color=#ac9c94]wu^[/color][color=#d5c1ba]$ [/color][color=#ebebeb]N[/color]
[color=#808080]              [/color][color=#a7a7a7]|[/color][color=#dbdbdb]N [/color][color=#e75c31]j[/color][color=#9f7467]_[/color][color=#b67967]j[/color][color=#fe855f]@[/color][color=#ff855f]@@@[/color][color=#eb8464]W[/color][color=#c2836f]w[/color][color=#c2846f]w[/color][color=#e38567]#[/color][color=#f28563]R[/color][color=#ff855f]@[/color][color=#ff855f]@[/color][color=#f98561]@[/color][color=#c3836f]w[/color][color=#a1847a]_[/color][color=#96827c]_-[/color][color=#c08571]j[/color][color=#d7846a]4[/color][color=#fe855f]@[/color][color=#ff855f]@@@@@[/color][color=#f88561]@R[/color][color=#e38467]R[/color][color=#ce8068]j[/color][color=#c97c66]w[/color][color=#b37c6d];^"[/color][color=#a98073]' [/color][color=#ae6f5c]'[/color][color=#bc6b51]^[/color][color=#af7765]'[/color][color=#ac8f83]u[/color][color=#a29892]-[/color][color=#a39e98]=[/color][color=#b0a9a2]|[/color][color=#bdb3a9]2[/color][color=#b9afa6]*[/color][color=#ada59e]*[/color][color=#a49d98]^[/color][color=#9e9994]^^[/color][color=#9f9791]'  [/color][color=#b86d56]r [/color][color=#e5e5e5]N[/color]
[color=#808080]              [/color][color=#ececec]0 [/color][color=#d36340]|[/color][color=#c5674a]j[/color][color=#e75c31]|[/color][color=#f97c55]0[/color][color=#fd8660]@[/color][color=#c58470]"[/color][color=#b68373]^[/color][color=#aa8377]' [/color][color=#aea09c]v[/color][color=#a3a09f], [/color][color=#b18374]j[/color][color=#ff855f]D[/color][color=#ff855f]@@@@D@[/color][color=#b98372]/[/color][color=#b88472]"[/color][color=#ed8664]J[/color][color=#ff855f]@[/color][color=#ff855f]@@@R[/color][color=#b28272]^[/color][color=#b57362]=[/color][color=#c96950]j[/color][color=#ee5f39]|[/color][color=#e65935]R[/color][color=#ce5e41]R[/color][color=#b66854]^  [/color][color=#a09288],[/color][color=#a49a93]'[/color][color=#bbb3aa]2[/color][color=#b4aea7]=[/color][color=#a39d98]^[/color][color=#a59c95]",[/color][color=#9f9085]_[/color][color=#a29186]=[/color][color=#a9978a]=[/color][color=#b09c8f]H[/color][color=#baa596]j[/color][color=#d3bba9]D[/color][color=#c1ae9f]?[/color][color=#b3a196]T[/color][color=#977d74]_ [/color][color=#a5a2a1]y[/color][color=#e0e0e0]M[/color]
[color=#808080]             [/color][color=#b9b9b9]J[/color][color=#cacaca]M[/color][color=#a27465]|[/color][color=#b16e5a]-[/color][color=#e05e36]D[/color][color=#e85e33]j[/color][color=#fe845e]@[/color][color=#ff855f]@[/color][color=#f78562]@[/color][color=#d3846a]W[/color][color=#ae8274],[/color][color=#94817a]_[/color][color=#91827d]__ [/color][color=#cc856d]y[/color][color=#fe855f]@[/color][color=#ff855f]@R[/color][color=#f48562]R[/color][color=#e98565]R[/color][color=#d88469]P[/color][color=#bd8370]T[/color][color=#ab8275],[/color][color=#f88561]@[/color][color=#ff855f]@[/color][color=#ff855f]@R[/color][color=#f6774f]R[/color][color=#f06c43]D[/color][color=#d26847]H [/color][color=#bc664f]^[/color][color=#af6b5a]'[/color][color=#a18076]_[/color][color=#a7a19b]y  [/color][color=#a39083]j[/color][color=#c9b3a1]R[/color][color=#b9b4ac]T[/color][color=#a59c95],[/color][color=#a29185],[/color][color=#b39b8a]j[/color][color=#c0a491]R[/color][color=#aa998e]=[/color][color=#a69990]=^[/color][color=#b1a8a0]T[/color][color=#b3aca4]^[/color][color=#b5aba2]"[/color][color=#bdafa5]TT  [/color][color=#a9a19f]y[/color][color=#d4d4d4]A[/color][color=#b1b1b1]"[/color]
[color=#808080]             [/color][color=#ececec]M [/color][color=#d3623f]H[/color][color=#b36d58]j[/color][color=#e75c32]|[/color][color=#f4734a]J[/color][color=#ff855f]@[/color][color=#ff855f]@@@@D@[/color][color=#e78566]@@@@[/color][color=#f18563]D[/color][color=#b88372]a[/color][color=#d78369]@[/color][color=#e28467]@[/color][color=#f08563]@[/color][color=#fd8560]@[/color][color=#ff855f]@[/color][color=#f97b54]R[/color][color=#f16e45]D[/color][color=#ea6137]U[/color][color=#e75c31]j[/color][color=#d6623e]R[/color][color=#ba6d55]^[/color][color=#a98274], [/color][color=#a18f83]r [/color][color=#e5d8ca]R[/color][color=#a39f9b]^[/color][color=#918781],[/color][color=#a58c7e]^[/color][color=#998d85]_[/color][color=#9a8c82]=[/color][color=#9f8e82]^[/color][color=#9f8f84]_.[/color][color=#988b82]-[/color][color=#b19b8b]=[/color][color=#b39d8d]H^^[/color][color=#b69f8f]H[/color][color=#a99689]^ [/color][color=#979797]_[/color][color=#b3b3b3]w[/color][color=#c5c5c5]#[/color][color=#c6c6c6]M[/color][color=#a0a0a0]'[/color]
[color=#808080]            [/color][color=#e3e3e3]0 [/color][color=#c2684c]| [/color][color=#e55c32]j[/color][color=#e96035]j[/color][color=#fe845e]@[/color][color=#ff855f]@@@@@D@@@@@@@DR[/color][color=#f27953]R[/color][color=#ea6b44]D[/color][color=#e45f36]j[/color][color=#dc5f39]R[/color][color=#bf694f]^[/color][color=#aa7e6f]_[/color][color=#ada199]y[/color][color=#c5bfb6]@[/color][color=#e2d9cc]@[/color][color=#e7ddd1]R[/color][color=#d9d1c6]N  [/color][color=#a29891]^   [/color][color=#9e8e83]_[/color][color=#b49e8f]u[/color][color=#b6a294]wmR[/color][color=#bda99b]R[/color][color=#beab9e]M[/color][color=#c5bbb0]P[/color][color=#b2ada7]^[/color][color=#adacaa]y[/color][color=#c4c4c4]p[/color][color=#c6c6c6]M[/color][color=#bdbdbd]T[/color][color=#9f9f9f]'[/color]
[color=#808080]           [/color][color=#cacaca]4[/color][color=#b8b8b8]M [/color][color=#cb6546]|[/color][color=#e15e36]D[/color][color=#e75d32]|[/color][color=#fa7c55]@[/color][color=#ff855f]@[/color][color=#ff855f]@@D[/color][color=#eb8464]R[/color][color=#d1856c]T[/color][color=#d3866c]7[/color][color=#f08664]T[/color][color=#ff855f]@[/color][color=#ff855f]@@@[/color][color=#f87a52]R[/color][color=#f16d44]D[/color][color=#d76845]H[/color][color=#bb6650]r  [/color][color=#968e89],[/color][color=#ac9d93]u [/color][color=#c9aa93]|[/color][color=#c6a58d]=j[/color][color=#dbbaa2]|[/color][color=#d1bba9]K[/color][color=#b4aea7]J[/color][color=#cfc7be]N   [/color][color=#a8978a]+[/color][color=#b39e90]H^[/color][color=#a29388]_[/color][color=#b4aaa0]a[/color][color=#b4aba3]A [/color][color=#9e9996],[/color][color=#b8b8b8]w[/color][color=#c8c8c8]A[/color][color=#c2c2c2]M[/color]
[color=#808080]          [/color][color=#aaaaaa]i[/color][color=#d6d6d6]N [/color][color=#b26957]=[/color][color=#bb644f]=[/color][color=#a07065]_[/color][color=#ae7b6b]'[/color][color=#fe855f]D[/color][color=#ff855f]@@@[/color][color=#bf8370]U[/color][color=#bf8471]R  J[/color][color=#ba7f6c]/[/color][color=#de7a5b]T[/color][color=#ec653c]|[/color][color=#e75c31]|[/color][color=#e25e35]D[/color][color=#c3684c]" [/color][color=#a9a59f]a[/color][color=#c4b2a5]@[/color][color=#bfa38f]U[/color][color=#978b83]_?[/color][color=#afa095]U[/color][color=#a39388]|[/color][color=#c39f86]|[/color][color=#c39f86]|[/color][color=#d1aa8f]j[/color][color=#d7ae92]DD[/color][color=#afa9a2]J[/color][color=#c9c2b9]N  [/color][color=#9f9186]_[/color][color=#b79f8f]R[/color][color=#af9d8f]"[/color][color=#aaa19b];[/color][color=#b6b6b5]y[/color][color=#c8c8c8]#[/color][color=#c2c2c2]M[/color][color=#a6a6a6]"[/color]
[color=#808080]          [/color][color=#ececec]M [/color][color=#d3563a]|[/color][color=#e74c2a]|[/color][color=#e14f2e]D[/color][color=#b76451]^ [/color][color=#fe855f]D[/color][color=#ff855f]@@@[/color][color=#dc8669]R [/color][color=#f2704e]R[/color][color=#dd6647]D[/color][color=#ba6650]= [/color][color=#af6f5b]'^[/color][color=#a67f71]_[/color][color=#918a85]_[/color][color=#a29287]=[/color][color=#9d8f84]-.[/color][color=#ada69f]?[/color][color=#c6b1a3]R[/color][color=#d7b7a1]@[/color][color=#9e8f84]_[/color][color=#ae9f94]! [/color][color=#bf9d85]j[/color][color=#c39f86]|[/color][color=#c6a188])[/color][color=#d6ae92]D[/color][color=#d7af93]D[/color][color=#c7a892]U[/color][color=#bcb6af]7[/color][color=#bcb6af]U w[/color][color=#c5c5c5]A[/color][color=#c4c4c4]M[/color][color=#a9a9a9]"[/color]
[color=#808080]         [/color][color=#e1e1e1]0[/color][color=#a29a98]-[/color][color=#d45539]|[/color][color=#e74c2a]|[/color][color=#e74c2a]| [/color][color=#9f8278],[/color][color=#f18563]@[/color][color=#ff855f]@[/color][color=#ff855f]@[/color][color=#ef8564]R[/color][color=#c3806b]^[/color][color=#ac7060]_[/color][color=#ce5e41]|[/color][color=#e7532d]jH  [/color][color=#9b9590]-[/color][color=#bbb2a9]R[/color][color=#c9beb3]M[/color][color=#cac0b5]M[/color][color=#c9b5a7]R[/color][color=#c6af9f]R[/color][color=#b6a498]*x[/color][color=#bba290]U[/color][color=#9a8f87]_[/color][color=#b19c8e]!  [/color][color=#ad9584]|[/color][color=#c39f86]|[/color][color=#c39f86]|[/color][color=#d3ac90]|[/color][color=#d7af93]D[/color][color=#d7af93]D[/color][color=#afa59d]H[/color][color=#e0d6ca]B[/color][color=#9e9b97]-[/color][color=#d2d2d2]4[/color][color=#acacac]w   [/color][color=#949494],[/color][color=#afafaf]w[/color][color=#bebebe]w[/color][color=#bebebe]ww[/color][color=#b3b3b3]w[/color][color=#a4a4a4];[/color][color=#8b8b8b]_[/color]
[color=#808080]        [/color][color=#b5b5b5]y[/color][color=#c8c8c8]N [/color][color=#e34e2d]D[/color][color=#d3563a]R  [/color][color=#f68561]B[/color][color=#e38467]R[/color][color=#e18264]T[/color][color=#e87551]D [/color][color=#bd654e]![/color][color=#ce5e41]R[/color][color=#b46956]^  [/color][color=#9a8f87]_[/color][color=#a6978d],[/color][color=#a7988e],[/color][color=#b7a395]A[/color][color=#b7a294]H[/color][color=#ae9b8e]^[/color][color=#a29389]^[/color][color=#998d84]^       j[/color][color=#c39f86]|[/color][color=#c39f86]|[/color][color=#d0a98e]1[/color][color=#d7af93]D[/color][color=#d6ae92]DD[/color][color=#b0aba5]J[/color][color=#ddd5c9]@ [/color][color=#f2f2f2]N [/color][color=#9b9b9b],[/color][color=#dbdbdb]M[/color][color=#afa6a4]?[/color][color=#b37865],[/color][color=#a27567]=[/color][color=#a77261]=[/color][color=#c16a4f]=  [/color][color=#b7a4a0]"[/color][color=#c5c3c3]T[/color][color=#c3c3c3]*[/color][color=#bbbbbb]w[/color][color=#989898]_[/color][color=#838383]_[/color]
[color=#808080]        [/color][color=#f2f2f2]M [/color][color=#c2654b]=[/color][color=#c4684c]=[/color][color=#b06f5b]-[/color][color=#b78170]w[/color][color=#d98469]@[/color][color=#cb836c]D [/color][color=#c2684c]|[/color][color=#e45d34]D [/color][color=#888584]_[/color][color=#a69a91]x[/color][color=#a2978f]=[/color][color=#a1968e]^',,[/color][color=#ad988a]=[/color][color=#b69f8f]m[/color][color=#b59e8e]R[/color][color=#b09b8c]H[/color][color=#a9978a]^[/color][color=#a49387]'[/color][color=#9f8f84]_    [/color][color=#949494]_ j[/color][color=#c39f86]|[/color][color=#c39f86]|[/color][color=#d0aa8e]1[/color][color=#d7af93]D[/color][color=#d7af93]DR[/color][color=#b8b2ab]U[/color][color=#e9dfd2]R [/color][color=#dedede]I [/color][color=#ededed]0 [/color][color=#c0694e]^[/color][color=#b76d57]^[/color][color=#c96647]|[/color][color=#e1714e]K[/color][color=#f37048]@[/color][color=#a88073],[/color][color=#ad6b5b]'[/color][color=#d95636]D[/color][color=#e2512f]D[/color][color=#cc5b41]H[/color][color=#b66c5c]=[/color][color=#af948e]^[/color][color=#b9b9b9]T[/color][color=#c2c2c2]M[/color][color=#c2c2c2]w[/color][color=#a6a6a6];[/color]
[color=#808080]        [/color][color=#dfdfdf]N [/color][color=#e75c31]|[/color][color=#e75c31]|j[/color][color=#f27047]D)[/color][color=#d46240]K[/color][color=#bd6d54]H   [/color][color=#a19288].[/color][color=#9e9086]=[/color][color=#a6968a]^[/color][color=#cfb29e]K[/color][color=#c4ad9d]R[/color][color=#b1a095]T[/color][color=#a7988d],  [/color][color=#a9978a]j^[/color][color=#a19288]'[/color][color=#9b9189]. [/color][color=#92908f]_[/color][color=#aeadad]y[/color][color=#c8c8c8]#[/color][color=#c5c5c5]M[/color][color=#d6d6d6]T[/color][color=#b6b6b6]H[/color][color=#a79283]j[/color][color=#c39f86]|[/color][color=#c39f86]|[/color][color=#d4ac91]D[/color][color=#d7af93]DDD[/color][color=#d9cdc1]U[/color][color=#d0c8be]}[/color][color=#b7b2ab]H[/color][color=#b3b3b3]J[/color][color=#c5c5c5]N[/color][color=#bababa]7L [/color][color=#a4a4a4]^[/color][color=#9b9897]_[/color][color=#c06a4f]![/color][color=#f37149]R[/color][color=#ff855f]@[/color][color=#cd856d]L [/color][color=#ea704f]0[/color][color=#f36540]@ [/color][color=#a37265]_[/color][color=#917972]_[/color][color=#9c7569]_[/color][color=#b56d58]=[/color][color=#a3948f]'[/color][color=#d5d5d5]9[/color][color=#aeaeae]w[/color]
[color=#808080]        [/color][color=#e4e4e4]N [/color][color=#e75c31]|[/color][color=#e75c31]||[/color][color=#df5f37]R[/color][color=#b1705b]^  [/color][color=#a3948a],[/color][color=#ac9d91]^[/color][color=#b8a699]|=[/color][color=#a69990]^[/color][color=#a29388]_j[/color][color=#bda390]|[/color][color=#b4a295]|[/color][color=#bfb5aa]a[/color][color=#bdb7af]M  [/color][color=#a4a09d];w[/color][color=#c2c2c2]A[/color][color=#c7c7c7]M[/color][color=#acacac]?   [/color][color=#e2e2e2]0 [/color][color=#b39784]|[/color][color=#c39f86]|[/color][color=#c5a087]j[/color][color=#d6ae92]D[/color][color=#d7af93]DDD[/color][color=#e5d7c9]B[/color][color=#c3bcb4]J[/color][color=#cac3ba]M[/color][color=#a6a6a6]J[/color][color=#d3d3d3]N [/color][color=#b0b0b0]"[/color][color=#dadada]N  [/color][color=#939393],[/color][color=#ad705d]'[/color][color=#ed673e]|[/color][color=#fa845f]@[/color][color=#b08274]w  [/color][color=#bd8370]|[/color][color=#fe845e]@[/color][color=#f97c55]@[/color][color=#f4734b]@[/color][color=#ee6940]U[/color][color=#e25e35]H [/color][color=#efefef]8[/color]
[color=#808080]        [/color][color=#dcdcdc]Y[/color][color=#a6a6a6]w[/color][color=#b86c54]![/color][color=#e75c31]|[/color][color=#d26341]H  [/color][color=#ac9d92]+[/color][color=#b3a79c]l[/color][color=#b7b0a9]m[/color][color=#aba59d]"[/color][color=#a09185]_[/color][color=#b79e8c]j[/color][color=#c5a895]KD [/color][color=#ad9b91]^[/color][color=#a48d84]. [/color][color=#909090]_[/color][color=#b9b9b9]w[/color][color=#cecece]M[/color][color=#a8a8a8]"       [/color][color=#eeeeee]M [/color][color=#c19e86]|[/color][color=#c39f86]|[/color][color=#caa58b]j[/color][color=#d7af93]D[/color][color=#d7af93]DDD[/color][color=#e7d8c9]R[/color][color=#eae0d3]@[/color][color=#cdc6bc]P[/color][color=#a2a2a2]J[/color][color=#e3e3e3]N[/color][color=#bebebe]w[/color][color=#c6c6c6]MT[/color][color=#a09893],[/color][color=#998c82]_-[/color][color=#a19185], [/color][color=#e8663e]R[/color][color=#ca826b]U[/color][color=#fa8560]B[/color][color=#fa8661]@[/color][color=#c2836f]^ R[/color][color=#d7846a]M^[/color][color=#c1755d]| [/color][color=#efefef]k[/color]
[color=#808080]         [/color][color=#c6c6c6]T[/color][color=#c7c7c7]N[/color][color=#a3867d]_[/color][color=#bb6b52]^[/color][color=#ac705e]=[/color][color=#aa7d6e].[/color][color=#9f7e73]_[/color][color=#a8867a],[/color][color=#9a776c]_[/color][color=#a97968]_[/color][color=#a97666]-[/color][color=#a47364]-  [/color][color=#af8f85];[/color][color=#bab0ad]y[/color][color=#c2c2c2]#[/color][color=#c9c9c9]M[/color][color=#aeaeae]?         [/color][color=#d6d6d6]4[/color][color=#a6a6a6]"[/color][color=#a89283]j[/color][color=#c39f86])[/color][color=#c39f86]|[/color][color=#d3ac90]D[/color][color=#d7af93]DDD[/color][color=#d7b094]j[/color][color=#e8dcce]B[/color][color=#eae0d3]@[/color][color=#c9c2b9]M [/color][color=#adaaa8]?[/color][color=#a29185],[/color][color=#b39a88]D[/color][color=#d0b7a3]a[/color][color=#cdbaaa]K[/color][color=#b4aaa0]^ [/color][color=#9a9a99],[/color][color=#8d8d8d]_ [/color][color=#dd6946]j[/color][color=#fe835d]R[/color][color=#ff855f]@[/color][color=#f38663]@[/color][color=#e88566]R[/color][color=#b6806f];[/color][color=#dc866f]@ [/color][color=#989898],[/color][color=#e1e1e1]M[/color]
[color=#808080]           [/color][color=#b0b0b0]^[/color][color=#c2c2c2]M[/color][color=#bfbfbf]*[/color][color=#bbb9b8]w[/color][color=#bcb5b3]wwww*[/color][color=#bebebe]M[/color][color=#bfbfbf]M[/color][color=#b5b5b5]T[/color][color=#9c9c9c]'            /[/color][color=#cccccc]M [/color][color=#c29f86]|[/color][color=#c39f86]|[/color][color=#caa58b]j[/color][color=#d7af93]D[/color][color=#d7af93]DDD[/color][color=#dab89f]j[/color][color=#c0bab2]M[/color][color=#c6bfb6]T[/color][color=#d9d0c5]@[/color][color=#b9ab9f]e[/color][color=#bca797]R[/color][color=#bbb1a8]y[/color][color=#b1aca6]R[/color][color=#a3a19e],[/color][color=#c4c4c4]p[/color][color=#d8d8d8]4[/color][color=#afafaf]w [/color][color=#a9a9a9]"[/color][color=#b4b4b4]1 [/color][color=#dd6a47]j[/color][color=#e58465]R [/color][color=#e27a5d]K[/color][color=#f3876b]R [/color][color=#aeaeae]i[/color][color=#d5d5d5]M[/color]
[color=#808080]                                   [/color][color=#adadad]i[/color][color=#d8d8d8]M [/color][color=#c09e86]j[/color][color=#c39f86])[/color][color=#c7a289]j[/color][color=#d6ae92]D[/color][color=#d7af93]DDDD[/color][color=#e5d5c4]K[/color][color=#b7b2ab]U[/color][color=#bab4ad]a[/color][color=#e8ded1]@[/color][color=#e8ded1]@[/color][color=#ded5c9]M[/color][color=#9d9b98].[/color][color=#c6c6c6]p[/color][color=#c7c7c7]M  T[/color][color=#c0c0c0]w  [/color][color=#9d8d88]_[/color][color=#b86c54]j[/color][color=#f2764f]B[/color][color=#cb9280]y  [/color][color=#a1a1a1],[/color][color=#e0e0e0]M[/color]
[color=#808080]                                  [/color][color=#bdbdbd]J[/color][color=#cfcfcf]M[/color][color=#908883]_[/color][color=#c09e86]j[/color][color=#c39f86]|[/color][color=#c9a48a]j[/color][color=#d6ae92]D[/color][color=#d7af93]DDDD[/color][color=#dbb9a1]j[/color][color=#e9dfd2]@[/color][color=#eae0d3]@[/color][color=#d1c9bf]M[/color][color=#bab5ad]x[/color][color=#cac3ba]M [/color][color=#e1e1e1]F[/color][color=#9e9e9e]-    [/color][color=#9f9f9f]'[/color][color=#d5d4d4]#[/color][color=#b2afae]w[/color][color=#ab7b6c]_[/color][color=#c79484]f[/color][color=#d6b2a7]M[/color][color=#c7b6b1]M[/color][color=#878786]_[/color][color=#b5b5b5]z[/color][color=#d5d5d5]M[/color]
[color=#808080]                                [/color][color=#909090]_[/color][color=#d7d7d7]#[/color][color=#aeadad]^[/color][color=#9e8e82]j[/color][color=#c29e86]j[/color][color=#c39f86]j[/color][color=#cda78d]j[/color][color=#d6ae92]D[/color][color=#d7af93]DDDD[/color][color=#d9b49a]1[/color][color=#e8ddcf]@[/color][color=#eae0d3]@[/color][color=#c0bab2]M[/color][color=#cac3ba]4[/color][color=#b8b2ac]M[/color][color=#a7a7a7]y[/color][color=#dcdcdc]M         [/color][color=#b3b3b3]?[/color][color=#bcbcbc]M[/color][color=#bcbcbc]MM[/color][color=#b2b2b2]?[/color]
[color=#808080]                              [/color][color=#959595],[/color][color=#cccccc]#[/color][color=#bfbfbe]M[/color][color=#988f88]_[/color][color=#b79a85]j[/color][color=#c39f86]|[/color][color=#c6a188])[/color][color=#d3ac90]D[/color][color=#d7af93]DDDDD[/color][color=#d8b398]U[/color][color=#e7dacb]@[/color][color=#e9dfd2]@[/color][color=#bab4ad]H[/color][color=#d2cac0]#[/color][color=#aca8a2]H[/color][color=#b5b5b5]/[/color][color=#d2d2d2]M[/color]
[color=#808080]                           [/color][color=#8f8f8f]_[/color][color=#b8b8b8]w[/color][color=#cdcdcd]M[/color][color=#b2b2b1]C[/color][color=#9c8f85]_[/color][color=#b69985]j[/color][color=#c39f86]|[/color][color=#c39f86])[/color][color=#cda68c]j[/color][color=#d6ae92]D[/color][color=#d7af93]DDDDD[/color][color=#d8b499]U[/color][color=#e7dbcc]@[/color][color=#e9dfd2]@[/color][color=#b9b4ad]M[/color][color=#d3ccc1]4[/color][color=#b4afa8]H[/color][color=#b0b0b0]y[/color][color=#d4d4d4]N[/color]
[color=#808080]                      [/color][color=#868686]_[/color][color=#9a9a9a],[/color][color=#b6b6b6]w[/color][color=#c2c2c2]#[/color][color=#c3c3c3]M[/color][color=#b2afae]^[/color][color=#9f938b]_[/color][color=#ac9484]j[/color][color=#b99a85]H[/color][color=#b99a85]j[/color][color=#c39f86])[/color][color=#cba58b]j[/color][color=#d5ad91]D[/color][color=#d7af93]DDDDDD[/color][color=#dbb9a0]j[/color][color=#e8dcce]@[/color][color=#eae0d3]@[/color][color=#bdb7b0]M[/color][color=#d1cabf]#[/color][color=#c7c0b7]R[/color][color=#9c9c9c],[/color][color=#e4e4e4]M[/color]
[color=#808080]                [/color][color=#cdcdcd]@[/color][color=#bebebe]M[/color][color=#bdbdbd]MMM[/color][color=#babab9]"[/color][color=#b5b2b0]?[/color][color=#a9a19b];[/color][color=#a3948a].[/color][color=#ab9585]=[/color][color=#b39784]R^j[/color][color=#ba9b85]j[/color][color=#c5a187]j[/color][color=#cda78c]j[/color][color=#d5ad92]D[/color][color=#d7af92]DDDDDDj[/color][color=#e0c8b4]B[/color][color=#e9dfd2]@[/color][color=#eae0d3]@[/color][color=#cfc8be]P[/color][color=#c0bab2]4P [/color][color=#ebebeb]M[/color]
[color=#808080]                N [/color][color=#ae9584]j[/color][color=#bc9c85]D[/color][color=#b99a85]H[/color][color=#ab9483]^[/color][color=#ac9484]|[/color][color=#a69183]'[/color][color=#ba9b85]j[/color][color=#b89a85]Hj[/color][color=#c6a288]|[/color][color=#cda78c]j[/color][color=#d3ac90]D[/color][color=#d6ae92]DDDDDDDD[/color][color=#dbbaa2]i[/color][color=#e7d9ca]@[/color][color=#eae0d3]@[/color][color=#eae0d3]@[/color][color=#d5cdc2]M[/color][color=#b4afa9]/[/color][color=#cfc8be]P [/color][color=#e6e6e6]F[/color]
[color=#808080]                 # [/color][color=#b39884]j[/color][color=#bc9b85]H[/color][color=#ad9584]=[/color][color=#b19785]=[/color][color=#b99c87]j[/color][color=#cba58b]|[/color][color=#d0aa8f]D[/color][color=#d5ae92]D[/color][color=#d7af93]DDDDDDDDD[/color][color=#d9b59b]U[/color][color=#e4d1bf]K[/color][color=#e9dfd2]@[/color][color=#e9dfd2]@@[/color][color=#bbb5ae]D[/color][color=#c6bfb7]4M[/color][color=#a2a2a2],[/color][color=#e0e0e0]M[/color]
[color=#808080]                  [/color][color=#dbdbdb]9[/color][color=#aaaaaa]w[/color][color=#a89689]?[/color][color=#d3ac92]R[/color][color=#d6ae92]DDDDDDDDDDDD[/color][color=#dab8a0]|[/color][color=#e4d0bf]K[/color][color=#e9dfd2]@[/color][color=#eadfd2]@[/color][color=#e3d9cd]M[/color][color=#c1bbb3]T[/color][color=#bfb9b1]a[/color][color=#d4ccc2]M [/color][color=#c8c8c8]4[/color][color=#c4c4c4]M[/color]
[color=#808080]                   [/color][color=#ababab]?[/color][color=#d5d5d5]N[/color][color=#a7a5a3];[/color][color=#aa9789]^[/color][color=#cca991]D[/color][color=#d6ae92]D[/color][color=#d7af93]DDDD[/color][color=#d0ab91]RDU[/color][color=#dfc5b0]U[/color][color=#e7d8c9]@[/color][color=#e9dfd2]@#[/color][color=#d1c9bf]M[/color][color=#dad2c6]W[/color][color=#ccc5bb]@[/color][color=#d6cdc3]M[/color][color=#a7a39f]^[/color][color=#b8b8b8]z[/color][color=#d3d3d3]M[/color]
[color=#808080]                     [/color][color=#a5a5a5]^[/color][color=#cbcbcb]M[/color][color=#c2c1c1]w[/color][color=#aaa39f];[/color][color=#ab998d]^[/color][color=#bea592]R[/color][color=#cfab91]R[/color][color=#cab19e]U[/color][color=#b1a8a0]u[/color][color=#aea9a2]u[/color][color=#dbd2c7]4[/color][color=#e8ded1]@[/color][color=#ccc5bb]w[/color][color=#e4dace]@[/color][color=#d3cbc1]@[/color][color=#d3cbc1]M[/color][color=#b8b3ac]T[/color][color=#a8a6a4];[/color][color=#c3c3c3]*[/color][color=#c9c9c9]M[/color]
[color=#808080]                        [/color][color=#9f9f9f]'[/color][color=#bababa]T[/color][color=#c2c2c2]M[/color][color=#c0c0c0]*[/color][color=#bdbdbc]w[/color][color=#b8b7b6]wuuu[/color][color=#bab9b7]yw[/color][color=#bebebe]x[/color][color=#c1c1c1]A[/color][color=#c5c5c5]M[/color][color=#a6a6a6]"[/color]
"""


def create_parser():
    bb_parser = forward_declaration()

    @generate
    def tag():
        start_tag = (
            string("[")
            >> (
                seq(regex(r"\w+") << string("="), regex(r"[^]]+")).map(tuple)
                | regex(r"\w+").map(lambda w: (w, None))
            )
            << string("]")
        )
        start = yield start_tag

        inner = yield bb_parser

        tag_name, _ = start
        end_tag = string("[/") >> string(tag_name) << string("]")
        yield end_tag

        return start, inner

    bb_parser.become((tag | regex(r"[^[]+")).many())
    return bb_parser


def pad_line(l, pad_char=" "):
    length = sum(map(len, l.split("%c")))
    return l + (80 - length) * pad_char


def build_log_string(parsed_original):
    def build_log_lists(parsed):
        str_list, format_list = [], []
        for x in parsed:
            if isinstance(x, tuple):
                (tagname, value), inner = x
                str_list.append("%c")
                format_list.append(
                    f'"font-family: monospace; background: black; ' f'{tagname}: {value};"'
                )
                new_str_list, new_format_list = build_log_lists(inner)
                str_list.extend(new_str_list)
                format_list.extend(new_format_list)
            elif isinstance(x, str):
                str_list.append(x)
            else:
                raise ValueError(f"Unexpected type {type(x)} of {x}")
        return str_list, format_list

    str_list, format_list = build_log_lists(parsed_original)
    ascii_art_string = "\n".join(map(pad_line, "".join(str_list).splitlines()))
    return f"""console.log(`{ascii_art_string}`, 
{", ".join(format_list)},
);
"""


def main(infile, outfile, export):
    bbcode = "[color=#EF3F3F]\n[/color]"
    if infile:
        with open(infile) as f:
            bbcode += f.read()
    else:
        bbcode += BBCODE
    bbcode += """
    
       [color=#EF3F3F]If you're seeing this, you should check out our careers page.[/color]
       [color=#EF3F3F]https://redballoonsecurity.com/company/careers/index.html[/color]
  
"""
    bbcode_parser = create_parser()
    parsed = bbcode_parser.parse(bbcode)
    output = build_log_string(parsed)

    if export:
        output = "export function printConsoleArt() {\n" + output + "\n}"

    if outfile:
        with open(outfile, "w") as f:
            f.write(output)
    else:
        print(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Parse styled BBCode and convert it to styled console.log output"
    )
    parser.add_argument("-f", "--filename", help="Load BBCode from this file")
    parser.add_argument("-o", "--outfile", help="Write to a file")
    parser.add_argument(
        "-e",
        "--export",
        action="store_true",
        help="Export a function to perform printing",
    )
    args = parser.parse_args()

    main(args.filename, args.outfile, args.export)
