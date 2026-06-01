//===- IdaDetect.cpp - IDA调试器检测注入Pass -------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// 本文件实现IDA调试器检测注入Pass，在程序入口点注入检测代码
// 通过读取 /proc/self/status 检测 IDA 调试器特征
// 检测到则强制终止进程
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Obfuscation/IdaDetect.h"
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

#define DEBUG_TYPE "idadetect"

using namespace llvm;

namespace {

struct IdaDetect : public ModulePass {
    static char ID;

    IdaDetect() : ModulePass(ID) {
        initializeIdaDetectPass(*PassRegistry::getPassRegistry());
    }

    StringRef getPassName() const override {
        return {"IdaDetect"};
    }

    bool runOnModule(Module &M) override;
    
    Function* createReportAndKillFunc(Module &M);
    Function* createIdaCheckFunc(Module &M, Function *ReportAndKillFunc);
};

}

char IdaDetect::ID = 0;

Function* IdaDetect::createReportAndKillFunc(Module &M) {
    LLVMContext &Ctx = M.getContext();
    
    Type *VoidTy = Type::getVoidTy(Ctx);
    Type *Int32Ty = Type::getInt32Ty(Ctx);
    PointerType *CharPtrTy = PointerType::get(Ctx, 0);
    
    FunctionType *FuncTy = FunctionType::get(VoidTy, {}, false);
    Function *Func = Function::Create(
        FuncTy,
        GlobalValue::InternalLinkage,
        M.getDataLayout().getProgramAddressSpace(),
        "ida_report_and_kill",
        &M
    );
    
    Func->addFnAttr(Attribute::NoInline);
    Func->addFnAttr(Attribute::OptimizeNone);
    
    BasicBlock *BB = BasicBlock::Create(Ctx, "entry", Func);
    IRBuilder<> Builder(BB);
    
    FunctionCallee PrintfFunc = M.getOrInsertFunction(
        "printf",
        FunctionType::get(Int32Ty, {CharPtrTy}, true)
    );
    
    FunctionCallee FflushFunc = M.getOrInsertFunction(
        "fflush",
        FunctionType::get(Int32Ty, {CharPtrTy}, false)
    );
    
    Constant *MsgStr = ConstantDataArray::getString(Ctx, "检测到IDA调试器!!!\n");
    GlobalVariable *MsgGV = new GlobalVariable(
        M,
        MsgStr->getType(),
        true,
        GlobalValue::PrivateLinkage,
        MsgStr,
        ".ida.msg"
    );
    Constant *MsgPtr = ConstantExpr::getBitCast(MsgGV, CharPtrTy);
    
    Builder.CreateCall(PrintfFunc, {MsgPtr});
    
    Constant *NullPtr = ConstantPointerNull::get(CharPtrTy);
    Builder.CreateCall(FflushFunc, {NullPtr});
    
    FunctionCallee GetpidFunc = M.getOrInsertFunction(
        "getpid",
        FunctionType::get(Int32Ty, {}, false)
    );
    
    FunctionCallee KillFunc = M.getOrInsertFunction(
        "kill",
        FunctionType::get(Int32Ty, {Int32Ty, Int32Ty}, false)
    );
    
    Value *Pid = Builder.CreateCall(GetpidFunc);
    Value *Sigkill = ConstantInt::get(Int32Ty, 9);
    Builder.CreateCall(KillFunc, {Pid, Sigkill});
    
    FunctionCallee AsmExitFunc = M.getOrInsertFunction("exit",
        FunctionType::get(Type::getVoidTy(M.getContext()), {Int32Ty}, false));
    Builder.CreateCall(AsmExitFunc, {ConstantInt::get(Int32Ty, 0)});
    
    Builder.CreateUnreachable();
    
    return Func;
}

Function* IdaDetect::createIdaCheckFunc(Module &M, Function *ReportAndKillFunc) {
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
        "ida_check",
        &M
    );
    
    Func->addFnAttr(Attribute::NoInline);
    
    BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", Func);
    BasicBlock *OpenOkBB = BasicBlock::Create(Ctx, "open_ok", Func);
    BasicBlock *OpenFailBB = BasicBlock::Create(Ctx, "open_fail", Func);
    BasicBlock *ReadOkBB = BasicBlock::Create(Ctx, "read_ok", Func);
    BasicBlock *FoundBB = BasicBlock::Create(Ctx, "found", Func);
    BasicBlock *ExitBB = BasicBlock::Create(Ctx, "exit", Func);
    
    IRBuilder<> Builder(EntryBB);
    
    FunctionCallee OpenFunc = M.getOrInsertFunction(
        "open",
        FunctionType::get(Int32Ty, {CharPtrTy, Int32Ty}, false)
    );
    
    auto makeString = [&](const char *str) -> Constant* {
        Constant *StrConst = ConstantDataArray::getString(Ctx, str);
        GlobalVariable *StrGV = new GlobalVariable(
            M, StrConst->getType(), true,
            GlobalValue::PrivateLinkage, StrConst,
            ".ida.str." + Twine(str)
        );
        return ConstantExpr::getBitCast(StrGV, CharPtrTy);
    };
    
    Constant *StatusPath = makeString("/proc/self/status");
    Value *O_RDONLY = ConstantInt::get(Int32Ty, 0);
    
    Value *Fd = Builder.CreateCall(OpenFunc, {StatusPath, O_RDONLY});
    Value *FdValid = Builder.CreateICmpNE(Fd, ConstantInt::get(Int32Ty, -1));
    Builder.CreateCondBr(FdValid, OpenOkBB, OpenFailBB);
    
    Builder.SetInsertPoint(OpenFailBB);
    Builder.CreateBr(ExitBB);
    
    Builder.SetInsertPoint(OpenOkBB);
    
    FunctionCallee ReadFunc = M.getOrInsertFunction(
        "read",
        FunctionType::get(Int64Ty, {Int32Ty, CharPtrTy, Int64Ty}, false)
    );
    
    FunctionCallee CloseFunc = M.getOrInsertFunction(
        "close",
        FunctionType::get(Int32Ty, {Int32Ty}, false)
    );
    
    Type *BufTy = ArrayType::get(Type::getInt8Ty(Ctx), 1024);
    Value *Buf = Builder.CreateAlloca(BufTy, nullptr, "buf");
    Value *BufPtr = Builder.CreateBitCast(Buf, CharPtrTy);
    
    Value *BytesRead = Builder.CreateCall(ReadFunc, {Fd, BufPtr, ConstantInt::get(Int64Ty, 1024)});
    Builder.CreateCall(CloseFunc, {Fd});
    
    Value *ReadValid = Builder.CreateICmpSGT(BytesRead, ConstantInt::get(Int64Ty, 0));
    Builder.CreateCondBr(ReadValid, ReadOkBB, ExitBB);
    
    Builder.SetInsertPoint(ReadOkBB);
    
    Constant *IdaSignature = makeString("IDA");
    
    FunctionCallee MemmemFunc = M.getOrInsertFunction(
        "memmem",
        FunctionType::get(CharPtrTy, {CharPtrTy, Int64Ty, CharPtrTy, Int64Ty}, false)
    );
    
    Value *IdaLen = ConstantInt::get(Int64Ty, 3);
    Value *Found = Builder.CreateCall(MemmemFunc, {BufPtr, BytesRead, IdaSignature, IdaLen});
    
    Value *FoundNotNull = Builder.CreateICmpNE(Found, ConstantPointerNull::get(CharPtrTy));
    Builder.CreateCondBr(FoundNotNull, FoundBB, ExitBB);
    
    Builder.SetInsertPoint(FoundBB);
    Builder.CreateCall(ReportAndKillFunc);
    Builder.CreateBr(ExitBB);
    
    Builder.SetInsertPoint(ExitBB);
    Builder.CreateRetVoid();
    
    return Func;
}

bool IdaDetect::runOnModule(Module &M) {
    if (isIRObfuscationDebugEnabled()) {
        errs() << "[DEBUG] IdaDetect: Injecting IDA detection\n";
    }

    Function *MainFunc = M.getFunction("main");
    if (!MainFunc || MainFunc->isDeclaration()) {
        return false;
    }

    if (MainFunc->empty()) {
        return false;
    }

    BasicBlock &EntryBB = MainFunc->getEntryBlock();
    
    Function *ReportAndKillFunc = createReportAndKillFunc(M);
    Function *CheckFunc = createIdaCheckFunc(M, ReportAndKillFunc);

    IRBuilder<> Builder(&EntryBB, EntryBB.getFirstInsertionPt());

    if (isIRObfuscationDebugEnabled()) {
        LLVMContext &Ctx = M.getContext();
        FunctionCallee PrintfFunc = M.getOrInsertFunction(
            "printf",
            FunctionType::get(Type::getInt32Ty(Ctx), {PointerType::get(Ctx, 0)}, true)
        );
        Constant *DebugStr = ConstantDataArray::getString(Ctx, "[DEBUG] IdaDetect: Checking IDA debugger...\n");
        GlobalVariable *DebugGV = new GlobalVariable(
            M, DebugStr->getType(), true,
            GlobalValue::PrivateLinkage, DebugStr,
            ".ida.debug"
        );
        Builder.CreateCall(PrintfFunc, {ConstantExpr::getBitCast(DebugGV, PointerType::get(Ctx, 0))});
    }

    Builder.CreateCall(CheckFunc);

    return true;
}

ModulePass *llvm::createIdaDetectPass() {
    return new IdaDetect();
}

INITIALIZE_PASS_BEGIN(IdaDetect, "idadetect", "Inject IDA debugger detection at program start", false, false)
INITIALIZE_PASS_END(IdaDetect, "idadetect", "Inject IDA debugger detection at program start", false, false)
