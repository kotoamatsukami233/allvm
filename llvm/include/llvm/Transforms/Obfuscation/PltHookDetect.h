//===- PltHookDetect.h - PLT Hook检测注入Pass ------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// 本文件声明PLT Hook检测注入Pass
// 检测GOT表中函数指针是否指向合法地址
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_OBFUSCATION_PLTHOOKDETECT_H
#define LLVM_TRANSFORMS_OBFUSCATION_PLTHOOKDETECT_H

#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"

namespace llvm {

class PassRegistry;

ModulePass *createPltHookDetectPass();
void initializePltHookDetectPass(PassRegistry &Registry);

} // namespace llvm

#endif // LLVM_TRANSFORMS_OBFUSCATION_PLTHOOKDETECT_H
