# TinyDBR

![UE4 Demo](https://github.com/Inori/TinyDBR/blob/master/ScreenShot/demo.jpg)

## What is TinyDBR?

TinyDBR is meant for tiny dynamic binary rewriter fox x86 instruction set.

This is a port to the [TinyInst](https://github.com/googleprojectzero/TinyInst) by Google Project Zero team to fit my own needs.

The original TinyInst works as a debuuger and the target process runs seperately as a debuggee.

While TinyDBR runs inter the target process and translate instructions right there.

## How TinyDBR works?

Currently, TinyDBR only support Windows and X64.

Both TinyInst and TinyDBR will protect the target's code to non-executable property, then an attempt to execute the target code will raise an execute exception.

But compared to TinyInst, which catch the exception and translate instructions in debug event loop of the debugger process, TinyDBR registers a VEH handler at the target process, and does all tranlation steps within the VEH handler.

Other parts are almost the same as the original TinyInst.



## TODO List:
1. ~~Refactory the public interface for easy usage.~~ Done.
2. Remove remote memory backup as we now have only one process.
3. ~~Support rewrite shellcode without modules.~~ Done.
4. Support rewrite multiple modules.
5. Support other platform.


