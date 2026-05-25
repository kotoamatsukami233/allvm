//===- PtraceDetect.h - Ptrace调试器检测注入Pass --------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// 本文件声明Ptrace调试器检测注入Pass
// 检测TracerPid和ptrace附加
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_OBFUSCATION_PTRACEDETECT_H
#define LLVM_TRANSFORMS_OBFUSCATION_PTRACEDETECT_H

#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"

namespace llvm {

class PassRegistry;

ModulePass *createPtraceDetectPass();
void initializePtraceDetectPass(PassRegistry &Registry);

} // namespace llvm

#endif // LLVM_TRANSFORMS_OBFUSCATION_PTRACEDETECT_H
