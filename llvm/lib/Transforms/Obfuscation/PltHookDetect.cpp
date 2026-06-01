//===- PltHookDetect.cpp - PLT Hook检测注入Pass --------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// 本文件实现PLT Hook检测注入Pass，在程序入口点注入检测代码
// 检测GOT表中函数指针是否指向合法地址
// 创建后台线程持续检测（随机5-8秒间隔）
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Obfuscation/PltHookDetect.h"
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

#define DEBUG_TYPE "plthookdetect"

using namespace llvm;

namespace {

struct PltHookDetect : public ModulePass {
    static char ID;

    PltHookDetect() : ModulePass(ID) {
        initializePltHookDetectPass(*PassRegistry::getPassRegistry());
    }

    StringRef getPassName() const override {
        return {"PltHookDetect"};
    }

    bool runOnModule(Module &M) override;
    
    Function* createReportAndKillFunc(Module &M);
    Function* createCheckPltHookFunc(Module &M);
    Function* createThreadCheckFunc(Module &M, Function *ReportAndKillFunc, Function *CheckFunc);
    Function* createStartThreadFunc(Module &M, Function *ThreadCheckFunc);
};

}

char PltHookDetect::ID = 0;

Function* PltHookDetect::createReportAndKillFunc(Module &M) {
    LLVMContext &Ctx = M.getContext();
    
    Type *VoidTy = Type::getVoidTy(Ctx);
    Type *Int32Ty = Type::getInt32Ty(Ctx);
    PointerType *CharPtrTy = PointerType::get(Ctx, 0);
    
    FunctionType *FuncTy = FunctionType::get(VoidTy, {}, false);
    Function *Func = Function::Create(
        FuncTy,
        GlobalValue::InternalLinkage,
        M.getDataLayout().getProgramAddressSpace(),
        "plthook_report_and_kill",
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
    
    Constant *MsgStr = ConstantDataArray::getString(Ctx, "检测到PLT Hook!!!\n");
    GlobalVariable *MsgGV = new GlobalVariable(
        M,
        MsgStr->getType(),
        true,
        GlobalValue::PrivateLinkage,
        MsgStr,
        ".plthook.msg"
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

Function* PltHookDetect::createCheckPltHookFunc(Module &M) {
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
        "check_plt_hook",
        &M
    );
    
    Func->addFnAttr(Attribute::NoInline);
    
    BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", Func);
    BasicBlock *OpenOkBB = BasicBlock::Create(Ctx, "open_ok", Func);
    BasicBlock *OpenFailBB = BasicBlock::Create(Ctx, "open_fail", Func);
    BasicBlock *LoopBB = BasicBlock::Create(Ctx, "loop", Func);
    BasicBlock *CheckLineBB = BasicBlock::Create(Ctx, "check_line", Func);
    BasicBlock *CheckPermBB = BasicBlock::Create(Ctx, "check_perm", Func);
    BasicBlock *FoundLibcBB = BasicBlock::Create(Ctx, "found_libc", Func);
    BasicBlock *CheckHookBB = BasicBlock::Create(Ctx, "check_hook", Func);
    BasicBlock *HookedBB = BasicBlock::Create(Ctx, "hooked", Func);
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
    
    FunctionCallee SscanfFunc = M.getOrInsertFunction(
        "sscanf",
        FunctionType::get(Int32Ty, {CharPtrTy, CharPtrTy}, true)
    );
    
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
            ".plthook.str." + Twine(str)
        );
        return ConstantExpr::getBitCast(StrGV, CharPtrTy);
    };
    
    Constant *MapsPath = makeString("/proc/self/maps");
    Constant *ReadMode = makeString("r");
    Constant *SscanfFmt = makeString("%lx-%lx %4s");
    Constant *LibcNeedle = makeString("libc.so");
    Constant *LibcPath = makeString("libc.so");
    Constant *OpenName = makeString("open");
    
    Value *Fp = Builder.CreateCall(FopenFunc, {MapsPath, ReadMode});
    Value *FpNotNull = Builder.CreateICmpNE(Fp, ConstantPointerNull::get(CharPtrTy));
    Builder.CreateCondBr(FpNotNull, OpenOkBB, OpenFailBB);
    
    Builder.SetInsertPoint(OpenFailBB);
    Builder.CreateRet(ConstantInt::get(Int32Ty, 0));
    
    Builder.SetInsertPoint(OpenOkBB);
    
    Type *LineBufTy = ArrayType::get(Int8Ty, 512);
    Value *LineBuf = Builder.CreateAlloca(LineBufTy, nullptr, "linebuf");
    Value *LineBufPtr = Builder.CreateBitCast(LineBuf, CharPtrTy);
    
    Type *StartBufTy = ArrayType::get(Int64Ty, 1);
    Value *StartBuf = Builder.CreateAlloca(StartBufTy, nullptr, "start");
    Value *StartPtr = Builder.CreateBitCast(StartBuf, CharPtrTy);
    
    Type *EndBufTy = ArrayType::get(Int64Ty, 1);
    Value *EndBuf = Builder.CreateAlloca(EndBufTy, nullptr, "end");
    Value *EndPtr = Builder.CreateBitCast(EndBuf, CharPtrTy);
    
    Type *PermBufTy = ArrayType::get(Int8Ty, 8);
    Value *PermBuf = Builder.CreateAlloca(PermBufTy, nullptr, "perm");
    Value *PermPtr = Builder.CreateBitCast(PermBuf, CharPtrTy);
    
    Builder.CreateBr(LoopBB);
    
    Builder.SetInsertPoint(LoopBB);
    
    Value *Line = Builder.CreateCall(FgetsFunc, {LineBufPtr, ConstantInt::get(Int32Ty, 512), Fp});
    Value *LineNotNull = Builder.CreateICmpNE(Line, ConstantPointerNull::get(CharPtrTy));
    
    BasicBlock *CloseAndExitBB = BasicBlock::Create(Ctx, "close_exit", Func);
    Builder.CreateCondBr(LineNotNull, CheckLineBB, CloseAndExitBB);
    
    Builder.SetInsertPoint(CloseAndExitBB);
    Builder.CreateCall(FcloseFunc, {Fp});
    Builder.CreateRet(ConstantInt::get(Int32Ty, 0));
    
    Builder.SetInsertPoint(CheckLineBB);
    
    Value *HasLibc = Builder.CreateCall(StrstrFunc, {LineBufPtr, LibcNeedle});
    Value *HasLibcNotNull = Builder.CreateICmpNE(HasLibc, ConstantPointerNull::get(CharPtrTy));
    Builder.CreateCondBr(HasLibcNotNull, CheckPermBB, LoopBB);
    
    Builder.SetInsertPoint(CheckPermBB);
    
    Builder.CreateCall(SscanfFunc, {LineBufPtr, SscanfFmt, StartPtr, EndPtr, PermPtr});
    
    Value *PermChar2 = Builder.CreateGEP(Int8Ty, PermBuf, {ConstantInt::get(Int64Ty, 0), ConstantInt::get(Int64Ty, 2)});
    Value *ExecFlag = Builder.CreateLoad(Int8Ty, PermChar2);
    Value *IsExecutable = Builder.CreateICmpEQ(ExecFlag, ConstantInt::get(Int8Ty, 'x'));
    Builder.CreateCondBr(IsExecutable, FoundLibcBB, LoopBB);
    
    Builder.SetInsertPoint(FoundLibcBB);
    
    Value *LibcStart = Builder.CreateLoad(Int64Ty, StartPtr);
    Value *LibcEnd = Builder.CreateLoad(Int64Ty, EndPtr);
    
    Builder.CreateCall(FcloseFunc, {Fp});
    Builder.CreateBr(CheckHookBB);
    
    Builder.SetInsertPoint(CheckHookBB);
    
    Value *RtldNoLoad = ConstantInt::get(Int32Ty, 4);
    Value *LibcHandle = Builder.CreateCall(DlopenFunc, {LibcPath, RtldNoLoad});
    
    BasicBlock *DoneBB = BasicBlock::Create(Ctx, "done", Func);
    BasicBlock *DlsymBB = BasicBlock::Create(Ctx, "dlsym", Func);
    
    Value *HandleNull = Builder.CreateICmpEQ(LibcHandle, ConstantPointerNull::get(CharPtrTy));
    Builder.CreateCondBr(HandleNull, DoneBB, DlsymBB);
    
    Builder.SetInsertPoint(DlsymBB);
    
    Value *OpenAddr = Builder.CreateCall(DlsymFunc, {LibcHandle, OpenName});
    
    Value *AddrNull = Builder.CreateICmpEQ(OpenAddr, ConstantPointerNull::get(CharPtrTy));
    Builder.CreateCondBr(AddrNull, DoneBB, ExitBB);
    
    Builder.SetInsertPoint(DoneBB);
    Builder.CreateRet(ConstantInt::get(Int32Ty, 0));
    
    Value *OpenAddrInt = Builder.CreatePtrToInt(OpenAddr, Int64Ty);
    
    Value *GeStart = Builder.CreateICmpUGE(OpenAddrInt, LibcStart);
    Value *LtEnd = Builder.CreateICmpULT(OpenAddrInt, LibcEnd);
    Value *InLibcRange = Builder.CreateAnd(GeStart, LtEnd);
    
    Builder.CreateCondBr(InLibcRange, ExitBB, HookedBB);
    
    Builder.SetInsertPoint(HookedBB);
    Builder.CreateRet(ConstantInt::get(Int32Ty, 1));
    
    Builder.SetInsertPoint(ExitBB);
    Builder.CreateRet(ConstantInt::get(Int32Ty, 0));
    
    return Func;
}

Function* PltHookDetect::createThreadCheckFunc(Module &M, Function *ReportAndKillFunc, Function *CheckFunc) {
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
        "plthook_thread_check",
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

Function* PltHookDetect::createStartThreadFunc(Module &M, Function *ThreadCheckFunc) {
    LLVMContext &Ctx = M.getContext();
    
    Type *VoidTy = Type::getVoidTy(Ctx);
    Type *Int32Ty = Type::getInt32Ty(Ctx);
    PointerType *CharPtrTy = PointerType::get(Ctx, 0);
    
    FunctionType *FuncTy = FunctionType::get(VoidTy, {}, false);
    Function *Func = Function::Create(
        FuncTy,
        GlobalValue::InternalLinkage,
        M.getDataLayout().getProgramAddressSpace(),
        "plthook_start_thread",
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

bool PltHookDetect::runOnModule(Module &M) {
    if (isIRObfuscationDebugEnabled()) {
        errs() << "[DEBUG] PltHookDetect: Injecting PLT hook detection\n";
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
    Function *CheckFunc = createCheckPltHookFunc(M);
    Function *ThreadCheckFunc = createThreadCheckFunc(M, ReportAndKillFunc, CheckFunc);
    Function *StartThreadFunc = createStartThreadFunc(M, ThreadCheckFunc);

    IRBuilder<> Builder(&EntryBB, EntryBB.getFirstInsertionPt());

    if (isIRObfuscationDebugEnabled()) {
        LLVMContext &Ctx = M.getContext();
        FunctionCallee PrintfFunc = M.getOrInsertFunction(
            "printf",
            FunctionType::get(Type::getInt32Ty(Ctx), {PointerType::get(Ctx, 0)}, true)
        );
        Constant *DebugStr = ConstantDataArray::getString(Ctx, "[DEBUG] PltHookDetect: Starting PLT hook detection thread...\n");
        GlobalVariable *DebugGV = new GlobalVariable(
            M, DebugStr->getType(), true,
            GlobalValue::PrivateLinkage, DebugStr,
            ".plthook.debug"
        );
        Builder.CreateCall(PrintfFunc, {ConstantExpr::getBitCast(DebugGV, PointerType::get(Ctx, 0))});
    }

    Builder.CreateCall(StartThreadFunc);

    return true;
}

ModulePass *llvm::createPltHookDetectPass() {
    return new PltHookDetect();
}

INITIALIZE_PASS_BEGIN(PltHookDetect, "plthookdetect", "Inject PLT hook detection at program start", false, false)
INITIALIZE_PASS_END(PltHookDetect, "plthookdetect", "Inject PLT hook detection at program start", false, false)
