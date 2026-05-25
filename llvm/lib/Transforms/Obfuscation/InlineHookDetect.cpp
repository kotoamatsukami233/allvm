//===- InlineHookDetect.cpp - Inline Hook检测注入Pass --------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// 本文件实现Inline Hook检测注入Pass，在程序入口点注入检测代码
// 检测关键函数入口字节是否被修改（如被替换为跳转指令）
// 创建后台线程持续检测（随机5-8秒间隔）
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Obfuscation/InlineHookDetect.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Obfuscation/ObfuscationPassManager.h"

#define DEBUG_TYPE "inlinehookdetect"

using namespace llvm;

namespace {

struct InlineHookDetect : public ModulePass {
    static char ID;

    InlineHookDetect() : ModulePass(ID) {
        initializeInlineHookDetectPass(*PassRegistry::getPassRegistry());
    }

    StringRef getPassName() const override {
        return {"InlineHookDetect"};
    }

    bool runOnModule(Module &M) override;
    
    Function* createReportAndKillFunc(Module &M);
    Function* createCheckInlineHookFunc(Module &M);
    Function* createThreadCheckFunc(Module &M, Function *ReportAndKillFunc, Function *CheckFunc);
    Function* createStartThreadFunc(Module &M, Function *ThreadCheckFunc);
};

}

char InlineHookDetect::ID = 0;

Function* InlineHookDetect::createReportAndKillFunc(Module &M) {
    LLVMContext &Ctx = M.getContext();
    
    Type *VoidTy = Type::getVoidTy(Ctx);
    Type *Int32Ty = Type::getInt32Ty(Ctx);
    PointerType *CharPtrTy = PointerType::get(Ctx, 0);
    
    FunctionType *FuncTy = FunctionType::get(VoidTy, {}, false);
    Function *Func = Function::Create(
        FuncTy,
        GlobalValue::InternalLinkage,
        M.getDataLayout().getProgramAddressSpace(),
        "inlinehook_report_and_kill",
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
    
    Constant *MsgStr = ConstantDataArray::getString(Ctx, "检测到Inline Hook!!!\n");
    GlobalVariable *MsgGV = new GlobalVariable(
        M,
        MsgStr->getType(),
        true,
        GlobalValue::PrivateLinkage,
        MsgStr,
        ".inlinehook.msg"
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
    
    FunctionType *AsmTy = FunctionType::get(VoidTy, {}, false);
    
    InlineAsm *Asm = InlineAsm::get(AsmTy, "brk #0", "", true, false);
    Builder.CreateCall(Asm);
    
    Builder.CreateUnreachable();
    
    return Func;
}

Function* InlineHookDetect::createCheckInlineHookFunc(Module &M) {
    LLVMContext &Ctx = M.getContext();
    
    Type *Int8Ty = Type::getInt8Ty(Ctx);
    Type *Int32Ty = Type::getInt32Ty(Ctx);
    PointerType *CharPtrTy = PointerType::get(Ctx, 0);
    
    FunctionType *FuncTy = FunctionType::get(Int32Ty, {}, false);
    Function *Func = Function::Create(
        FuncTy,
        GlobalValue::InternalLinkage,
        M.getDataLayout().getProgramAddressSpace(),
        "check_inline_hook",
        &M
    );
    
    Func->addFnAttr(Attribute::NoInline);
    
    BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", Func);
    BasicBlock *HookedBB = BasicBlock::Create(Ctx, "hooked", Func);
    BasicBlock *ExitBB = BasicBlock::Create(Ctx, "exit", Func);
    
    IRBuilder<> Builder(EntryBB);
    
    FunctionCallee DlopenFunc = M.getOrInsertFunction(
        "dlopen",
        FunctionType::get(CharPtrTy, {CharPtrTy, Int32Ty}, false)
    );
    
    FunctionCallee DlsymFunc = M.getOrInsertFunction(
        "dlsym",
        FunctionType::get(CharPtrTy, {CharPtrTy, CharPtrTy}, false)
    );
    
    auto makeString = [&](const char *str) -> Constant* {
        Constant *StrConst = ConstantDataArray::getString(Ctx, str);
        GlobalVariable *StrGV = new GlobalVariable(
            M, StrConst->getType(), true,
            GlobalValue::PrivateLinkage, StrConst,
            ".inlinehook.str." + Twine(str)
        );
        return ConstantExpr::getBitCast(StrGV, CharPtrTy);
    };
    
    Constant *LibcPath = makeString("libc.so");
    Constant *OpenName = makeString("open");
    
    Value *RtldNoLoad = ConstantInt::get(Int32Ty, 4);
    
    Value *LibcHandle = Builder.CreateCall(DlopenFunc, {LibcPath, RtldNoLoad});
    
    BasicBlock *DoneBB = BasicBlock::Create(Ctx, "done", Func);
    BasicBlock *CheckBB = BasicBlock::Create(Ctx, "check", Func);
    
    Value *HandleNull = Builder.CreateICmpEQ(LibcHandle, ConstantPointerNull::get(CharPtrTy));
    Builder.CreateCondBr(HandleNull, DoneBB, CheckBB);
    
    Builder.SetInsertPoint(CheckBB);
    
    Value *OpenAddr = Builder.CreateCall(DlsymFunc, {LibcHandle, OpenName});
    
    Value *AddrNull = Builder.CreateICmpEQ(OpenAddr, ConstantPointerNull::get(CharPtrTy));
    
    BasicBlock *CheckByteBB = BasicBlock::Create(Ctx, "check_byte", Func);
    Builder.CreateCondBr(AddrNull, DoneBB, CheckByteBB);
    
    Builder.SetInsertPoint(CheckByteBB);
    
    Value *Byte0Ptr = Builder.CreateBitCast(OpenAddr, PointerType::get(Ctx, 0));
    Value *Byte0 = Builder.CreateLoad(Int8Ty, Byte0Ptr);
    
    Value *B_Opcode = ConstantInt::get(Int8Ty, 0xFC);
    Value *B_Expected = ConstantInt::get(Int8Ty, 0x14);
    Value *Byte0Masked = Builder.CreateAnd(Byte0, B_Opcode);
    Value *IsBranch = Builder.CreateICmpEQ(Byte0Masked, B_Expected);
    
    Builder.CreateCondBr(IsBranch, HookedBB, ExitBB);
    
    Builder.SetInsertPoint(HookedBB);
    Builder.CreateRet(ConstantInt::get(Int32Ty, 1));
    
    Builder.SetInsertPoint(ExitBB);
    Builder.CreateRet(ConstantInt::get(Int32Ty, 0));
    
    Builder.SetInsertPoint(DoneBB);
    Builder.CreateRet(ConstantInt::get(Int32Ty, 0));
    
    return Func;
}

Function* InlineHookDetect::createThreadCheckFunc(Module &M, Function *ReportAndKillFunc, Function *CheckFunc) {
    LLVMContext &Ctx = M.getContext();
    
    Type *VoidTy = Type::getVoidTy(Ctx);
    Type *Int32Ty = Type::getInt32Ty(Ctx);
    Type *Int64Ty = Type::getInt64Ty(Ctx);
    PointerType *CharPtrTy = PointerType::get(Ctx, 0);
    
    FunctionType *FuncTy = FunctionType::get(VoidTy, {CharPtrTy}, false);
    Function *Func = Function::Create(
        FuncTy,
        GlobalValue::InternalLinkage,
        M.getDataLayout().getProgramAddressSpace(),
        "inlinehook_thread_check",
        &M
    );
    
    Func->addFnAttr(Attribute::NoInline);
    
    BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", Func);
    BasicBlock *LoopBB = BasicBlock::Create(Ctx, "loop", Func);
    BasicBlock *HookedBB = BasicBlock::Create(Ctx, "hooked", Func);
    BasicBlock *SleepBB = BasicBlock::Create(Ctx, "sleep", Func);
    BasicBlock *ExitBB = BasicBlock::Create(Ctx, "exit", Func);
    
    IRBuilder<> Builder(EntryBB);
    
    FunctionCallee SrandFunc = M.getOrInsertFunction(
        "srand",
        FunctionType::get(VoidTy, {Int32Ty}, false)
    );
    
    FunctionCallee TimeFunc = M.getOrInsertFunction(
        "time",
        FunctionType::get(Int64Ty, {CharPtrTy}, false)
    );
    
    Value *TimeVal = Builder.CreateCall(TimeFunc, {ConstantPointerNull::get(CharPtrTy)});
    Value *TimeInt = Builder.CreateTrunc(TimeVal, Int32Ty);
    Builder.CreateCall(SrandFunc, {TimeInt});
    
    Builder.CreateBr(LoopBB);
    
    Builder.SetInsertPoint(LoopBB);
    
    Value *Hooked = Builder.CreateCall(CheckFunc);
    Value *IsHooked = Builder.CreateICmpNE(Hooked, ConstantInt::get(Int32Ty, 0));
    Builder.CreateCondBr(IsHooked, HookedBB, SleepBB);
    
    Builder.SetInsertPoint(HookedBB);
    Builder.CreateCall(ReportAndKillFunc);
    Builder.CreateBr(ExitBB);
    
    Builder.SetInsertPoint(SleepBB);
    
    FunctionCallee RandFunc = M.getOrInsertFunction(
        "rand",
        FunctionType::get(Int32Ty, {}, false)
    );
    
    FunctionCallee UsleepFunc = M.getOrInsertFunction(
        "usleep",
        FunctionType::get(Int32Ty, {Int32Ty}, false)
    );
    
    Value *RandVal = Builder.CreateCall(RandFunc);
    Value *Mod4 = Builder.CreateURem(RandVal, ConstantInt::get(Int32Ty, 4));
    Value *DelaySec = Builder.CreateAdd(Mod4, ConstantInt::get(Int32Ty, 5));
    Value *DelayUsec = Builder.CreateMul(DelaySec, ConstantInt::get(Int32Ty, 1000000));
    Builder.CreateCall(UsleepFunc, {DelayUsec});
    
    Builder.CreateBr(LoopBB);
    
    Builder.SetInsertPoint(ExitBB);
    Builder.CreateRetVoid();
    
    return Func;
}

Function* InlineHookDetect::createStartThreadFunc(Module &M, Function *ThreadCheckFunc) {
    LLVMContext &Ctx = M.getContext();
    
    Type *VoidTy = Type::getVoidTy(Ctx);
    Type *Int32Ty = Type::getInt32Ty(Ctx);
    PointerType *CharPtrTy = PointerType::get(Ctx, 0);
    
    FunctionType *FuncTy = FunctionType::get(VoidTy, {}, false);
    Function *Func = Function::Create(
        FuncTy,
        GlobalValue::InternalLinkage,
        M.getDataLayout().getProgramAddressSpace(),
        "inlinehook_start_thread",
        &M
    );
    
    Func->addFnAttr(Attribute::NoInline);
    
    BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", Func);
    BasicBlock *ExitBB = BasicBlock::Create(Ctx, "exit", Func);
    
    IRBuilder<> Builder(EntryBB);
    
    Type *PthreadTy = StructType::create(Ctx, "pthread_t");
    Value *Thread = Builder.CreateAlloca(PthreadTy, nullptr, "thread");
    
    FunctionCallee PthreadCreateFunc = M.getOrInsertFunction(
        "pthread_create",
        FunctionType::get(Int32Ty, {CharPtrTy, CharPtrTy, CharPtrTy, CharPtrTy}, false)
    );
    
    Value *ThreadPtr = Builder.CreateBitCast(Thread, CharPtrTy);
    Value *ThreadFuncPtr = Builder.CreateBitCast(ThreadCheckFunc, CharPtrTy);
    
    Builder.CreateCall(PthreadCreateFunc, {
        ThreadPtr,
        ConstantPointerNull::get(CharPtrTy),
        ThreadFuncPtr,
        ConstantPointerNull::get(CharPtrTy)
    });
    
    Builder.CreateBr(ExitBB);
    
    Builder.SetInsertPoint(ExitBB);
    Builder.CreateRetVoid();
    
    return Func;
}

bool InlineHookDetect::runOnModule(Module &M) {
    if (isIRObfuscationDebugEnabled()) {
        errs() << "[DEBUG] InlineHookDetect: Injecting inline hook detection\n";
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
    Function *CheckFunc = createCheckInlineHookFunc(M);
    Function *ThreadCheckFunc = createThreadCheckFunc(M, ReportAndKillFunc, CheckFunc);
    Function *StartThreadFunc = createStartThreadFunc(M, ThreadCheckFunc);

    IRBuilder<> Builder(&EntryBB, EntryBB.getFirstInsertionPt());

    if (isIRObfuscationDebugEnabled()) {
        LLVMContext &Ctx = M.getContext();
        FunctionCallee PrintfFunc = M.getOrInsertFunction(
            "printf",
            FunctionType::get(Type::getInt32Ty(Ctx), {PointerType::get(Ctx, 0)}, true)
        );
        Constant *DebugStr = ConstantDataArray::getString(Ctx, "[DEBUG] InlineHookDetect: Starting inline hook detection thread...\n");
        GlobalVariable *DebugGV = new GlobalVariable(
            M, DebugStr->getType(), true,
            GlobalValue::PrivateLinkage, DebugStr,
            ".inlinehook.debug"
        );
        Builder.CreateCall(PrintfFunc, {ConstantExpr::getBitCast(DebugGV, PointerType::get(Ctx, 0))});
    }

    Builder.CreateCall(StartThreadFunc);

    return true;
}

ModulePass *llvm::createInlineHookDetectPass() {
    return new InlineHookDetect();
}

INITIALIZE_PASS_BEGIN(InlineHookDetect, "inlinehookdetect", "Inject inline hook detection at program start", false, false)
INITIALIZE_PASS_END(InlineHookDetect, "inlinehookdetect", "Inject inline hook detection at program start", false, false)
