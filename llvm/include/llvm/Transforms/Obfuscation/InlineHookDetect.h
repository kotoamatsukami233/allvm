//===- InlineHookDetect.h - Inline Hook检测注入Pass ------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// 本文件声明Inline Hook检测注入Pass
// 检测关键函数入口字节是否被修改
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_OBFUSCATION_INLINEHOOKDETECT_H
#define LLVM_TRANSFORMS_OBFUSCATION_INLINEHOOKDETECT_H

#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"

namespace llvm {

class PassRegistry;

ModulePass *createInlineHookDetectPass();
void initializeInlineHookDetectPass(PassRegistry &Registry);

} // namespace llvm

#endif // LLVM_TRANSFORMS_OBFUSCATION_INLINEHOOKDETECT_H
