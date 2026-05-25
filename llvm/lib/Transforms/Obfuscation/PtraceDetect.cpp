//===- PtraceDetect.cpp - Ptrace调试器检测注入Pass ------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// 本文件实现Ptrace调试器检测注入Pass，在程序入口点注入检测代码
// 创建后台线程持续检测TracerPid和ptrace附加（随机5-8秒间隔）
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Obfuscation/PtraceDetect.h"
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
#include "llvm/Transforms/Obfuscation/ObfuscationPassManager.h"

#define DEBUG_TYPE "ptracedetect"

using namespace llvm;

namespace {

struct PtraceDetect : public ModulePass {
    static char ID;

    PtraceDetect() : ModulePass(ID) {
        initializePtraceDetectPass(*PassRegistry::getPassRegistry());
    }

    StringRef getPassName() const override {
        return {"PtraceDetect"};
    }

    bool runOnModule(Module &M) override;
    
    Function* createReportAndKillFunc(Module &M);
    Function* createGetTracerPidFunc(Module &M);
    Function* createThreadCheckFunc(Module &M, Function *ReportAndKillFunc, Function *GetTracerPidFunc);
    Function* createStartThreadFunc(Module &M, Function *ThreadCheckFunc);
};

}

char PtraceDetect::ID = 0;

Function* PtraceDetect::createReportAndKillFunc(Module &M) {
    LLVMContext &Ctx = M.getContext();
    
    Type *VoidTy = Type::getVoidTy(Ctx);
    Type *Int32Ty = Type::getInt32Ty(Ctx);
    PointerType *CharPtrTy = PointerType::get(Ctx, 0);
    
    FunctionType *FuncTy = FunctionType::get(VoidTy, {}, false);
    Function *Func = Function::Create(
        FuncTy,
        GlobalValue::InternalLinkage,
        M.getDataLayout().getProgramAddressSpace(),
        "ptrace_report_and_kill",
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
    
    Constant *MsgStr = ConstantDataArray::getString(Ctx, "检测到调试器附加!!!\n");
    GlobalVariable *MsgGV = new GlobalVariable(
        M,
        MsgStr->getType(),
        true,
        GlobalValue::PrivateLinkage,
        MsgStr,
        ".ptrace.msg"
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

Function* PtraceDetect::createGetTracerPidFunc(Module &M) {
    LLVMContext &Ctx = M.getContext();
    
    Type *Int8Ty = Type::getInt8Ty(Ctx);
    Type *Int32Ty = Type::getInt32Ty(Ctx);
    Type *Int64Ty = Type::getInt64Ty(Ctx);
    PointerType *CharPtrTy = PointerType::get(Ctx, 0);
    
    FunctionType *FuncTy = FunctionType::get(Int32Ty, {}, false);
    Function *Func = Function::Create(
        FuncTy,
        GlobalValue::InternalLinkage,
        M.getDataLayout().getProgramAddressSpace(),
        "get_tracer_pid",
        &M
    );
    
    Func->addFnAttr(Attribute::NoInline);
    
    BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", Func);
    BasicBlock *OpenOkBB = BasicBlock::Create(Ctx, "open_ok", Func);
    BasicBlock *OpenFailBB = BasicBlock::Create(Ctx, "open_fail", Func);
    BasicBlock *LoopBB = BasicBlock::Create(Ctx, "loop", Func);
    BasicBlock *CheckLineBB = BasicBlock::Create(Ctx, "check_line", Func);
    BasicBlock *FoundBB = BasicBlock::Create(Ctx, "found", Func);
    BasicBlock *ExitBB = BasicBlock::Create(Ctx, "exit", Func);
    
    IRBuilder<> Builder(EntryBB);
    
    FunctionCallee FopenFunc = M.getOrInsertFunction(
        "fopen",
        FunctionType::get(CharPtrTy, {CharPtrTy, CharPtrTy}, false)
    );
    
    FunctionCallee FgetsFunc = M.getOrInsertFunction(
        "fgets",
        FunctionType::get(CharPtrTy, {CharPtrTy, Int32Ty, CharPtrTy}, false)
    );
    
    FunctionCallee FcloseFunc = M.getOrInsertFunction(
        "fclose",
        FunctionType::get(Int32Ty, {CharPtrTy}, false)
    );
    
    FunctionCallee StrstrFunc = M.getOrInsertFunction(
        "strstr",
        FunctionType::get(CharPtrTy, {CharPtrTy, CharPtrTy}, false)
    );
    
    FunctionCallee AtoiFunc = M.getOrInsertFunction(
        "atoi",
        FunctionType::get(Int32Ty, {CharPtrTy}, false)
    );
    
    auto makeString = [&](const char *str) -> Constant* {
        Constant *StrConst = ConstantDataArray::getString(Ctx, str);
        GlobalVariable *StrGV = new GlobalVariable(
            M, StrConst->getType(), true,
            GlobalValue::PrivateLinkage, StrConst,
            ".ptrace.str." + Twine(str)
        );
        return ConstantExpr::getBitCast(StrGV, CharPtrTy);
    };
    
    Constant *StatusPath = makeString("/proc/self/status");
    Constant *ReadMode = makeString("r");
    Constant *TracerPidKey = makeString("TracerPid:");
    
    Value *Fp = Builder.CreateCall(FopenFunc, {StatusPath, ReadMode});
    Value *FpNotNull = Builder.CreateICmpNE(Fp, ConstantPointerNull::get(CharPtrTy));
    Builder.CreateCondBr(FpNotNull, OpenOkBB, OpenFailBB);
    
    Builder.SetInsertPoint(OpenFailBB);
    Builder.CreateRet(ConstantInt::get(Int32Ty, -1));
    
    Builder.SetInsertPoint(OpenOkBB);
    
    Type *LineBufTy = ArrayType::get(Int8Ty, 256);
    Value *LineBuf = Builder.CreateAlloca(LineBufTy, nullptr, "linebuf");
    Value *LineBufPtr = Builder.CreateBitCast(LineBuf, CharPtrTy);
    
    Builder.CreateBr(LoopBB);
    
    Builder.SetInsertPoint(LoopBB);
    
    Value *Line = Builder.CreateCall(FgetsFunc, {LineBufPtr, ConstantInt::get(Int32Ty, 256), Fp});
    Value *LineNotNull = Builder.CreateICmpNE(Line, ConstantPointerNull::get(CharPtrTy));
    Builder.CreateCondBr(LineNotNull, CheckLineBB, ExitBB);
    
    Builder.SetInsertPoint(CheckLineBB);
    
    Value *Found = Builder.CreateCall(StrstrFunc, {LineBufPtr, TracerPidKey});
    Value *FoundNotNull = Builder.CreateICmpNE(Found, ConstantPointerNull::get(CharPtrTy));
    Builder.CreateCondBr(FoundNotNull, FoundBB, LoopBB);
    
    Builder.SetInsertPoint(FoundBB);
    
    Value *ValuePtr = Builder.CreateGEP(Int8Ty, LineBufPtr, {ConstantInt::get(Int64Ty, 10)});
    Value *TracerPid = Builder.CreateCall(AtoiFunc, {ValuePtr});
    Builder.CreateCall(FcloseFunc, {Fp});
    Builder.CreateRet(TracerPid);
    
    Builder.SetInsertPoint(ExitBB);
    Builder.CreateCall(FcloseFunc, {Fp});
    Builder.CreateRet(ConstantInt::get(Int32Ty, -1));
    
    return Func;
}

Function* PtraceDetect::createThreadCheckFunc(Module &M, Function *ReportAndKillFunc, Function *GetTracerPidFunc) {
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
        "ptrace_thread_check",
        &M
    );
    
    Func->addFnAttr(Attribute::NoInline);
    
    BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", Func);
    BasicBlock *LoopBB = BasicBlock::Create(Ctx, "loop", Func);
    BasicBlock *TracerFoundBB = BasicBlock::Create(Ctx, "tracer_found", Func);
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
    
    Value *TracerPid = Builder.CreateCall(GetTracerPidFunc);
    Value *TracerActive = Builder.CreateICmpSGT(TracerPid, ConstantInt::get(Int32Ty, 0));
    Builder.CreateCondBr(TracerActive, TracerFoundBB, SleepBB);
    
    Builder.SetInsertPoint(TracerFoundBB);
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

Function* PtraceDetect::createStartThreadFunc(Module &M, Function *ThreadCheckFunc) {
    LLVMContext &Ctx = M.getContext();
    
    Type *VoidTy = Type::getVoidTy(Ctx);
    Type *Int32Ty = Type::getInt32Ty(Ctx);
    PointerType *CharPtrTy = PointerType::get(Ctx, 0);
    
    FunctionType *FuncTy = FunctionType::get(VoidTy, {}, false);
    Function *Func = Function::Create(
        FuncTy,
        GlobalValue::InternalLinkage,
        M.getDataLayout().getProgramAddressSpace(),
        "ptrace_start_thread",
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

bool PtraceDetect::runOnModule(Module &M) {
    if (isIRObfuscationDebugEnabled()) {
        errs() << "[DEBUG] PtraceDetect: Injecting ptrace detection\n";
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
    Function *GetTracerPidFunc = createGetTracerPidFunc(M);
    Function *ThreadCheckFunc = createThreadCheckFunc(M, ReportAndKillFunc, GetTracerPidFunc);
    Function *StartThreadFunc = createStartThreadFunc(M, ThreadCheckFunc);

    IRBuilder<> Builder(&EntryBB, EntryBB.getFirstInsertionPt());

    LLVMContext &Ctx = M.getContext();

    if (isIRObfuscationDebugEnabled()) {
        FunctionCallee PrintfFunc = M.getOrInsertFunction(
            "printf",
            FunctionType::get(Type::getInt32Ty(Ctx), {PointerType::get(Ctx, 0)}, true)
        );
        Constant *DebugStr = ConstantDataArray::getString(Ctx, "[DEBUG] PtraceDetect: Starting ptrace detection thread...\n");
        GlobalVariable *DebugGV = new GlobalVariable(
            M, DebugStr->getType(), true,
            GlobalValue::PrivateLinkage, DebugStr,
            ".ptrace.debug"
        );
        Builder.CreateCall(PrintfFunc, {ConstantExpr::getBitCast(DebugGV, PointerType::get(Ctx, 0))});
    }

    Builder.CreateCall(StartThreadFunc);

    return true;
}

ModulePass *llvm::createPtraceDetectPass() {
    return new PtraceDetect();
}

INITIALIZE_PASS_BEGIN(PtraceDetect, "ptracedetect", "Inject ptrace debugger detection at program start", false, false)
INITIALIZE_PASS_END(PtraceDetect, "ptracedetect", "Inject ptrace debugger detection at program start", false, false)
