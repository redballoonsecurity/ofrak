# Contributing to OFRAK

Red Balloon Security is excited for developers and security researchers to contribute to this repository.

As provided by Clause #3 in [our license](LICENSE), by submitting a Pull Request you are providing
Red Balloon Security, Inc with certain rights to your contribution, and you attest that you are
authorized to do so by anyone who has claims to the content.

Red Balloon Security will not accept Pull Requests nor add software to this repository that reveals information about a
third party's intellectual property, proprietary formats, or protocols, _unless_ they are approved by the (verified)
owner before being created.

Such ownership verification, non-technical questions, concerns, or comments about anything other than
the committed source code should be directed to [ofrak@redballoonsecurity.com](mailto:ofrak@redballoonsecurity.com).

Want to contribute, but not sure where to start? Take a look at our [outstanding issues](https://github.com/redballoonsecurity/ofrak/issues) and [collaborate with us and other community developers on Slack](https://join.slack.com/t/ofrak/shared_invite/zt-1er7hircg-3mBEESUPV~00~Ao5in4EpQ)!

## Issues

For small fixes in docs, or typos, you probably won't need to create an issue first, but when in doubt please create one.

If you have a feature proposal or very large fix for an existing problem, we recommend creating an issue first to discuss it beforehand.
This lets you check that your pull request won't get denied because it is out of the scope or breaks the rules, before you spend the time creating it!

### Issue Template

We have issue templates! The more thought you put into yours, the more likely we are to help solve your problem or get the requested feature(s) in.

Please fill out the following questionnaires clearly and concisely depending on your request:

### For bugs

Before submitting a bug report please search for your issue. Add a :+1: and maybe a comment with more details if it is also affecting you.

### For features

Before submitting a feature request please search for your issue. Add a :+1: if you would also like to see this functionality implemented.

### For maintenance

Before submitting a maintenance request please search for your issue. Add a :+1: if you would also like to see this functionality implemented.

#### Example:
**What is the problem?**
*The infinite loop modifier is not injecting an infinite loop! <Traceback goes here>*
  - Platform: *Darwin-21.6.0-x86_64-i386-64bit*
  - Python environment:
```
dependency_one==0.01
dependency_two==1.3
dependency_three==3.7
dependency_four==1.0
# ...
```
**If you've discovered it, what is the root cause of the problem?**
*The OS X version of this weird toolchain does not support `b .` syntax*

**How often does it happen?**
*Every time :(*

**What are the steps to reproduce the issue?**
Ideally, give us a short script that reproduces the issue.

```c
/**
 * Compiled using weird-arch-none-eabi-gcc v1.336 from <URL>:
 *  /usr/local/bin/weird-arch-none-eabi-gcc add_things.c -o add_things.elf -O0
 */
void add_things(void)
{
  // I expect the InfiniteLoopModifier to replace this function
  // with a "branch to self", or b . instruction.
  int a = 1;
  int b = 2;
  return a + 5;
}

int main(int argc, char **argv)
{
   add_things();
   return 0;
}
```
```python
from ofrak import OFRAKContext, OFRAK
import ofrak_binary_ninja
from ofrak.core import ComplexBlock, ProgramAttributes
from infinite_loops import InfiniteLoopModifier

async def main(ofrak_context: OFRAKContext, add_things_program: str):
  root_resource = await ofrak_context.create_root_resource_from_file(add_things_program)
  await root_resource.unpack_recursively(do_not_unpack=(ComplexBlock,))
  await root_resource.analyze(ProgramAttributes)
  await root_resource.run(InfiniteLoopModifier, "add_things") # things break here!
  await root_resource.flush_to_disk("add_things_looped.elf")

if __name__ == "__main__":
    ofrak = OFRAK()
    ofrak.discover(ofrak_binary_ninja)
    ofrak.run(main, "add_things.elf")
```
**How would you implement this fix?**
*Upgrade to version 1.337 of this compiler (where they've added support for `b .` instructions) when Darwin platforms are detected.*

**Are there any (reasonable) alternative approaches?**
*Not really!*

**Are you interested in implementing it yourself?**
*Yes, I'd like to!*

## Pull Requests and Code Review

Please link your Pull Request to an outstanding issue if one exists.

The packages in this repository maintain 100% test coverage, either at the statement or function level. This test coverage is enforced in the CI pipeline. Pull Requests that do not meet this requirement will not be merged.

### Pull Request Guidelines (for everyone)

For now, every Pull Request will require at least one review by one of the current maintainers:
- @whyitfor
- @EdwardLarson
- @andresito00
- @rbs-jacob (frontend)

1. Please be respectful. Remember to discuss the merits of the idea, not the individual. Disrespectful behavior will not be tolerated.
2. Please back your code review suggestions with technical reasoning.
3. If the value of your code review suggestion is subjective, please use words like "I think...".
4. Please install and run the `pre-commit` hooks. (See below.)
5. If you have to write a long-winded explanation in the review, we expect to see some code comments.
6. Please keep your contributions within the scope of the proposed fix, feature, or maintenance task, though a little clean-up in the space you're working in is appreciated.
7. Please keep your contributions to a reasonable review size. When reviewing, it can take developers a little over an hour to get through a few hundred lines of code and find most defects.
8. The following packages maintain changelogs: [ofrak](./ofrak/CHANGELOG.md), [ofrak_io](./ofrak_io/CHANGELOG.md), [ofrak_patch_maker](./ofrak_patch_maker/CHANGELOG.md), [ofrak_type](./ofrak_type/CHANGELOG.md).). If applicable, please update the `Unreleased` section of each changelog as part of your Pull Request.

### Python Coding Standard
Please see our [coding standard document](https://ofrak.com/docs/contributor-guide/getting-started.html) for functional and stylistic expectations. It is still evolving, but has a lower probability of changing.

There may be rule-breaking content in the repository now, but that does not mean that the standard should not be followed.

We'd prefer for the review discussion to be dedicated to logical correctness, completeness, and performance.
