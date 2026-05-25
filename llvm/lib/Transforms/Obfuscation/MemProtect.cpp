//===- MemProtect.cpp - 内存保护注入Pass ----------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// 本文件实现内存保护注入Pass，在程序入口点注入保护代码
// 禁用core dump和锁定内存防止dump
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Obfuscation/MemProtect.h"
#include "llvm/Transforms/Obfuscation/ObfuscationPassManager.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"

#define DEBUG_TYPE "memprotect"

using namespace llvm;

namespace {

struct MemProtect : public ModulePass {
    static char ID;

    MemProtect() : ModulePass(ID) {
        initializeMemProtectPass(*PassRegistry::getPassRegistry());
    }

    StringRef getPassName() const override {
        return {"MemProtect"};
    }

    bool runOnModule(Module &M) override;
    
    Function* createProtectFunc(Module &M);
};

}

char MemProtect::ID = 0;

Function* MemProtect::createProtectFunc(Module &M) {
    LLVMContext &Ctx = M.getContext();
    
    Type *VoidTy = Type::getVoidTy(Ctx);
    Type *Int32Ty = Type::getInt32Ty(Ctx);
    Type *Int64Ty = Type::getInt64Ty(Ctx);
    PointerType *CharPtrTy = PointerType::get(Ctx, 0);
    
    FunctionType *FuncTy = FunctionType::get(VoidTy, {}, false);
    Function *Func = Function::Create(
        FuncTy,
        GlobalValue::InternalLinkage,
        M.getDataLayout().getProgramAddressSpace(),
        "mem_protect",
        &M
    );
    
    Func->addFnAttr(Attribute::NoInline);
    
    BasicBlock *BB = BasicBlock::Create(Ctx, "entry", Func);
    IRBuilder<> Builder(BB);
    
    Type *RlimitTy = StructType::create(Ctx, "rlimit");
    StructType *RlimitStruct = cast<StructType>(RlimitTy);
    RlimitStruct->setBody({Int64Ty, Int64Ty});
    
    Value *Rl = Builder.CreateAlloca(RlimitStruct, nullptr, "rl");
    
    Value *RlimCurPtr = Builder.CreateGEP(RlimitStruct, Rl, {ConstantInt::get(Int32Ty, 0), ConstantInt::get(Int32Ty, 0)});
    Builder.CreateStore(ConstantInt::get(Int64Ty, 0), RlimCurPtr);
    
    Value *RlimMaxPtr = Builder.CreateGEP(RlimitStruct, Rl, {ConstantInt::get(Int32Ty, 0), ConstantInt::get(Int32Ty, 1)});
    Builder.CreateStore(ConstantInt::get(Int64Ty, 0), RlimMaxPtr);
    
    FunctionCallee SetrlimitFunc = M.getOrInsertFunction(
        "setrlimit",
        FunctionType::get(Int32Ty, {Int32Ty, CharPtrTy}, false)
    );
    
    Value *RlPtr = Builder.CreateBitCast(Rl, CharPtrTy);
    Builder.CreateCall(SetrlimitFunc, {ConstantInt::get(Int32Ty, 4), RlPtr});
    
    FunctionCallee MlockallFunc = M.getOrInsertFunction(
        "mlockall",
        FunctionType::get(Int32Ty, {Int32Ty}, false)
    );
    
    Builder.CreateCall(MlockallFunc, {ConstantInt::get(Int32Ty, 3)});
    
    Builder.CreateRetVoid();
    
    return Func;
}

bool MemProtect::runOnModule(Module &M) {
    if (!isLicenseValidated()) return false;

    if (isIRObfuscationDebugEnabled()) {
        errs() << "[DEBUG] MemProtect: Injecting memory protection\n";
    }
    Function *MainFunc = M.getFunction("main");
    if (!MainFunc || MainFunc->isDeclaration()) {
        return false;
    }

    if (MainFunc->empty()) {
        return false;
    }

    BasicBlock &EntryBB = MainFunc->getEntryBlock();
    
    Function *ProtectFunc = createProtectFunc(M);

    IRBuilder<> Builder(&EntryBB, EntryBB.getFirstInsertionPt());
    
    LLVMContext &Ctx = M.getContext();
    
    if (isIRObfuscationDebugEnabled()) {
        FunctionCallee PrintfFunc = M.getOrInsertFunction(
            "printf",
            FunctionType::get(Type::getInt32Ty(Ctx), {PointerType::get(Ctx, 0)}, true)
        );
        Constant *DebugStr = ConstantDataArray::getString(Ctx, "[DEBUG] MemProtect: Applying memory protection...\n");
        GlobalVariable *DebugGV = new GlobalVariable(
            M, DebugStr->getType(), true,
            GlobalValue::PrivateLinkage, DebugStr,
            ".memprotect.debug"
        );
        Builder.CreateCall(PrintfFunc, {ConstantExpr::getBitCast(DebugGV, PointerType::get(Ctx, 0))});
    }
    
    Builder.CreateCall(ProtectFunc);

    return true;
}

ModulePass *llvm::createMemProtectPass() {
    return new MemProtect();
}

INITIALIZE_PASS_BEGIN(MemProtect, "memprotect", "Inject memory protection at program start", false, false)
INITIALIZE_PASS_END(MemProtect, "memprotect", "Inject memory protection at program start", false, false)
