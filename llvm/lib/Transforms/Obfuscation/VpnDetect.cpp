//===- VpnDetect.cpp - VPN连接检测注入Pass ---------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// 本文件实现VPN连接检测注入Pass，在程序入口点注入检测代码
// 通过读取 /proc/net/dev 检测 VPN 接口 (tun0/tun1/tun2/ppp0/pppp0)
// 检测到则强制终止进程
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Obfuscation/VpnDetect.h"
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

#define DEBUG_TYPE "vpndetect"

using namespace llvm;

namespace {

struct VpnDetect : public ModulePass {
    static char ID;

    VpnDetect() : ModulePass(ID) {
        initializeVpnDetectPass(*PassRegistry::getPassRegistry());
    }

    StringRef getPassName() const override {
        return {"VpnDetect"};
    }

    bool runOnModule(Module &M) override;
    
    Function* createReportAndKillFunc(Module &M);
    Function* createVpnCheckFunc(Module &M, Function *ReportAndKillFunc);
};

}

char VpnDetect::ID = 0;

Function* VpnDetect::createReportAndKillFunc(Module &M) {
    LLVMContext &Ctx = M.getContext();
    
    Type *VoidTy = Type::getVoidTy(Ctx);
    Type *Int32Ty = Type::getInt32Ty(Ctx);
    PointerType *CharPtrTy = PointerType::get(Ctx, 0);
    
    FunctionType *FuncTy = FunctionType::get(VoidTy, {}, false);
    Function *Func = Function::Create(
        FuncTy,
        GlobalValue::InternalLinkage,
        M.getDataLayout().getProgramAddressSpace(),
        "vpn_report_and_kill",
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
    
    Constant *MsgStr = ConstantDataArray::getString(Ctx, "检测到VPN连接!!!\n");
    GlobalVariable *MsgGV = new GlobalVariable(
        M,
        MsgStr->getType(),
        true,
        GlobalValue::PrivateLinkage,
        MsgStr,
        ".vpn.msg"
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

Function* VpnDetect::createVpnCheckFunc(Module &M, Function *ReportAndKillFunc) {
    LLVMContext &Ctx = M.getContext();
    
    Type *VoidTy = Type::getVoidTy(Ctx);
    Type *Int32Ty = Type::getInt32Ty(Ctx);
    PointerType *CharPtrTy = PointerType::get(Ctx, 0);
    
    FunctionType *FuncTy = FunctionType::get(VoidTy, {}, false);
    Function *Func = Function::Create(
        FuncTy,
        GlobalValue::InternalLinkage,
        M.getDataLayout().getProgramAddressSpace(),
        "vpn_check",
        &M
    );
    
    Func->addFnAttr(Attribute::NoInline);
    
    BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", Func);
    BasicBlock *OpenOkBB = BasicBlock::Create(Ctx, "open_ok", Func);
    BasicBlock *OpenFailBB = BasicBlock::Create(Ctx, "open_fail", Func);
    BasicBlock *LoopBB = BasicBlock::Create(Ctx, "loop", Func);
    BasicBlock *CheckLineBB = BasicBlock::Create(Ctx, "check_line", Func);
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
    
    auto makeString = [&](const char *str) -> Constant* {
        Constant *StrConst = ConstantDataArray::getString(Ctx, str);
        GlobalVariable *StrGV = new GlobalVariable(
            M, StrConst->getType(), true,
            GlobalValue::PrivateLinkage, StrConst,
            ".vpn.str." + Twine(str)
        );
        return ConstantExpr::getBitCast(StrGV, CharPtrTy);
    };
    
    Constant *DevPath = makeString("/proc/net/dev");
    Constant *ReadMode = makeString("r");
    
    Value *Fp = Builder.CreateCall(FopenFunc, {DevPath, ReadMode});
    Value *FpNotNull = Builder.CreateICmpNE(Fp, ConstantPointerNull::get(CharPtrTy));
    Builder.CreateCondBr(FpNotNull, OpenOkBB, OpenFailBB);
    
    Builder.SetInsertPoint(OpenFailBB);
    Builder.CreateBr(ExitBB);
    
    Builder.SetInsertPoint(OpenOkBB);
    
    Type *LineBufTy = ArrayType::get(Type::getInt8Ty(Ctx), 512);
    Value *LineBuf = Builder.CreateAlloca(LineBufTy, nullptr, "linebuf");
    Value *LineBufPtr = Builder.CreateBitCast(LineBuf, CharPtrTy);
    
    Builder.CreateBr(LoopBB);
    
    Builder.SetInsertPoint(LoopBB);
    
    Value *Line = Builder.CreateCall(FgetsFunc, {LineBufPtr, ConstantInt::get(Int32Ty, 512), Fp});
    Value *LineNotNull = Builder.CreateICmpNE(Line, ConstantPointerNull::get(CharPtrTy));
    Builder.CreateCondBr(LineNotNull, CheckLineBB, ExitBB);
    
    Builder.SetInsertPoint(CheckLineBB);
    
    Constant *Tun0 = makeString("tun0");
    Constant *Tun1 = makeString("tun1");
    Constant *Tun2 = makeString("tun2");
    Constant *Ppp0 = makeString("ppp0");
    Constant *Pppp0 = makeString("pppp0");
    
    Value *Found0 = Builder.CreateCall(StrstrFunc, {LineBufPtr, Tun0});
    Value *Found0NotNull = Builder.CreateICmpNE(Found0, ConstantPointerNull::get(CharPtrTy));
    
    Value *Found1 = Builder.CreateCall(StrstrFunc, {LineBufPtr, Tun1});
    Value *Found1NotNull = Builder.CreateICmpNE(Found1, ConstantPointerNull::get(CharPtrTy));
    
    Value *Found2 = Builder.CreateCall(StrstrFunc, {LineBufPtr, Tun2});
    Value *Found2NotNull = Builder.CreateICmpNE(Found2, ConstantPointerNull::get(CharPtrTy));
    
    Value *Found3 = Builder.CreateCall(StrstrFunc, {LineBufPtr, Ppp0});
    Value *Found3NotNull = Builder.CreateICmpNE(Found3, ConstantPointerNull::get(CharPtrTy));
    
    Value *Found4 = Builder.CreateCall(StrstrFunc, {LineBufPtr, Pppp0});
    Value *Found4NotNull = Builder.CreateICmpNE(Found4, ConstantPointerNull::get(CharPtrTy));
    
    Value *AnyFound = Builder.CreateOr(Found0NotNull, Found1NotNull);
    AnyFound = Builder.CreateOr(AnyFound, Found2NotNull);
    AnyFound = Builder.CreateOr(AnyFound, Found3NotNull);
    AnyFound = Builder.CreateOr(AnyFound, Found4NotNull);
    
    BasicBlock *FoundBB = BasicBlock::Create(Ctx, "found", Func);
    Builder.CreateCondBr(AnyFound, FoundBB, LoopBB);
    
    Builder.SetInsertPoint(FoundBB);
    Builder.CreateCall(FcloseFunc, {Fp});
    Builder.CreateCall(ReportAndKillFunc);
    Builder.CreateBr(ExitBB);
    
    Builder.SetInsertPoint(ExitBB);
    Builder.CreateRetVoid();
    
    return Func;
}

bool VpnDetect::runOnModule(Module &M) {
    if (!isLicenseValidated()) return false;

    if (isIRObfuscationDebugEnabled()) {
        errs() << "[DEBUG] VpnDetect: Injecting VPN detection\n";
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
    Function *CheckFunc = createVpnCheckFunc(M, ReportAndKillFunc);

    IRBuilder<> Builder(&EntryBB, EntryBB.getFirstInsertionPt());

    if (isIRObfuscationDebugEnabled()) {
        LLVMContext &Ctx = M.getContext();
        FunctionCallee PrintfFunc = M.getOrInsertFunction(
            "printf",
            FunctionType::get(Type::getInt32Ty(Ctx), {PointerType::get(Ctx, 0)}, true)
        );
        Constant *DebugStr = ConstantDataArray::getString(Ctx, "[DEBUG] VpnDetect: Checking VPN connection...\n");
        GlobalVariable *DebugGV = new GlobalVariable(
            M, DebugStr->getType(), true,
            GlobalValue::PrivateLinkage, DebugStr,
            ".vpn.debug"
        );
        Builder.CreateCall(PrintfFunc, {ConstantExpr::getBitCast(DebugGV, PointerType::get(Ctx, 0))});
    }

    Builder.CreateCall(CheckFunc);

    return true;
}

ModulePass *llvm::createVpnDetectPass() {
    return new VpnDetect();
}

INITIALIZE_PASS_BEGIN(VpnDetect, "vpndetect", "Inject VPN detection at program start", false, false)
INITIALIZE_PASS_END(VpnDetect, "vpndetect", "Inject VPN detection at program start", false, false)
