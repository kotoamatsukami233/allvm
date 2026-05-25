//===- MemProtect.h - 内存保护注入Pass ------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// 本文件声明内存保护注入Pass
// 禁用core dump和锁定内存防止dump
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_OBFUSCATION_MEMPROTECT_H
#define LLVM_TRANSFORMS_OBFUSCATION_MEMPROTECT_H

#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"

namespace llvm {

class PassRegistry;

ModulePass *createMemProtectPass();
void initializeMemProtectPass(PassRegistry &Registry);

} // namespace llvm

#endif // LLVM_TRANSFORMS_OBFUSCATION_MEMPROTECT_H
