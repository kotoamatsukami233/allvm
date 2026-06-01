//===- BanDump.cpp - 禁用内存dump注入Pass ----------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// 本文件实现禁用内存dump注入Pass，在程序入口点注入保护代码
// 通过读取 /proc/self/maps 找到可执行内存区域
// 使用 mprotect 系统调用移除读权限，防止内存被dump
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Obfuscation/BanDump.h"
#include "llvm/Transforms/Obfuscation/ObfuscationPassManager.h"
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

#define DEBUG_TYPE "bandump"

using namespace llvm;

namespace {

struct BanDump : public ModulePass {
    static char ID;

    BanDump() : ModulePass(ID) {
        initializeBanDumpPass(*PassRegistry::getPassRegistry());
    }

    StringRef getPassName() const override {
        return {"BanDump"};
    }

    bool runOnModule(Module &M) override;
    
    Function* createBanDumpFunc(Module &M);
};

}

char BanDump::ID = 0;

Function* BanDump::createBanDumpFunc(Module &M) {
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
        "ban_dump",
        &M
    );
    
    Func->addFnAttr(Attribute::NoInline);
    
    BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", Func);
    BasicBlock *OpenOkBB = BasicBlock::Create(Ctx, "open_ok", Func);
    BasicBlock *OpenFailBB = BasicBlock::Create(Ctx, "open_fail", Func);
    BasicBlock *LoopBB = BasicBlock::Create(Ctx, "loop", Func);
    BasicBlock *ReadOkBB = BasicBlock::Create(Ctx, "read_ok", Func);
    BasicBlock *CheckLineBB = BasicBlock::Create(Ctx, "check_line", Func);
    BasicBlock *FoundRxBB = BasicBlock::Create(Ctx, "found_rx", Func);
    BasicBlock *ParseHeadBB = BasicBlock::Create(Ctx, "parse_head", Func);
    BasicBlock *ParseTailBB = BasicBlock::Create(Ctx, "parse_tail", Func);
    BasicBlock *CallMprotectBB = BasicBlock::Create(Ctx, "call_mprotect", Func);
    BasicBlock *NextLineBB = BasicBlock::Create(Ctx, "next_line", Func);
    BasicBlock *CloseAndExitBB = BasicBlock::Create(Ctx, "close_and_exit", Func);
    BasicBlock *ExitBB = BasicBlock::Create(Ctx, "exit", Func);
    
    IRBuilder<> Builder(EntryBB);
    
    FunctionCallee FopenFunc = M.getOrInsertFunction(
        "fopen",
        FunctionType::get(CharPtrTy, {CharPtrTy, CharPtrTy}, false)
    );
    
    int strCounter = 0;
    auto makeString = [&](const char *str) -> Constant* {
        Constant *StrConst = ConstantDataArray::getString(Ctx, str);
        GlobalVariable *StrGV = new GlobalVariable(
            M, StrConst->getType(), true,
            GlobalValue::PrivateLinkage, StrConst,
            ".bandump.str." + Twine(strCounter++)
        );
        return ConstantExpr::getBitCast(StrGV, CharPtrTy);
    };
    
    Constant *MapsPath = makeString("/proc/self/maps");
    Constant *ReadMode = makeString("r");
    
    Value *Fp = Builder.CreateCall(FopenFunc, {MapsPath, ReadMode});
    Value *FpNotNull = Builder.CreateICmpNE(Fp, ConstantPointerNull::get(CharPtrTy));
    Builder.CreateCondBr(FpNotNull, OpenOkBB, OpenFailBB);
    
    Builder.SetInsertPoint(OpenFailBB);
    Builder.CreateBr(ExitBB);
    
    Builder.SetInsertPoint(OpenOkBB);
    
    Type *LineBufTy = ArrayType::get(Type::getInt8Ty(Ctx), 1024);
    Value *LineBuf = Builder.CreateAlloca(LineBufTy, nullptr, "linebuf");
    Value *LineBufPtr = Builder.CreateBitCast(LineBuf, CharPtrTy);
    
    Builder.CreateBr(LoopBB);
    
    Builder.SetInsertPoint(LoopBB);
    
    FunctionCallee FgetsFunc = M.getOrInsertFunction(
        "fgets",
        FunctionType::get(CharPtrTy, {CharPtrTy, Int32Ty, CharPtrTy}, false)
    );
    
    Value *Line = Builder.CreateCall(FgetsFunc, {LineBufPtr, ConstantInt::get(Int32Ty, 1024), Fp});
    Value *LineNotNull = Builder.CreateICmpNE(Line, ConstantPointerNull::get(CharPtrTy));
    Builder.CreateCondBr(LineNotNull, ReadOkBB, CloseAndExitBB);
    
    Builder.SetInsertPoint(ReadOkBB);
    
    FunctionCallee StrstrFunc = M.getOrInsertFunction(
        "strstr",
        FunctionType::get(CharPtrTy, {CharPtrTy, CharPtrTy}, false)
    );
    
    Constant *RxNeedle = makeString("r-x");
    Value *FoundRx = Builder.CreateCall(StrstrFunc, {LineBufPtr, RxNeedle});
    Value *HasRx = Builder.CreateICmpNE(FoundRx, ConstantPointerNull::get(CharPtrTy));
    Builder.CreateCondBr(HasRx, FoundRxBB, LoopBB);
    
    Builder.SetInsertPoint(FoundRxBB);
    
    FunctionCallee StrtokRFunc = M.getOrInsertFunction(
        "strtok_r",
        FunctionType::get(CharPtrTy, {CharPtrTy, CharPtrTy, CharPtrTy}, false)
    );
    
    Constant *DashDelim = makeString("-");
    Type *SaveptrTy = PointerType::get(Ctx, 0);
    Value *Saveptr = Builder.CreateAlloca(SaveptrTy, nullptr, "saveptr");
    Value *SaveptrPtr = Builder.CreateBitCast(Saveptr, CharPtrTy);
    
    Value *HeadToken = Builder.CreateCall(StrtokRFunc, {LineBufPtr, DashDelim, SaveptrPtr});
    Value *HeadTokenNotNull = Builder.CreateICmpNE(HeadToken, ConstantPointerNull::get(CharPtrTy));
    Builder.CreateCondBr(HeadTokenNotNull, ParseHeadBB, NextLineBB);
    
    Builder.SetInsertPoint(ParseHeadBB);
    
    FunctionCallee StrtoulFunc = M.getOrInsertFunction(
        "strtoul",
        FunctionType::get(Int64Ty, {CharPtrTy, CharPtrTy, Int32Ty}, false)
    );
    
    Value *HeadAddr = Builder.CreateCall(StrtoulFunc, {HeadToken, ConstantPointerNull::get(CharPtrTy), ConstantInt::get(Int32Ty, 16)});
    
    Constant *SpaceDelim = makeString(" r-x");
    Value *TailToken = Builder.CreateCall(StrtokRFunc, {ConstantPointerNull::get(CharPtrTy), SpaceDelim, SaveptrPtr});
    Value *TailTokenNotNull = Builder.CreateICmpNE(TailToken, ConstantPointerNull::get(CharPtrTy));
    Builder.CreateCondBr(TailTokenNotNull, ParseTailBB, NextLineBB);
    
    Builder.SetInsertPoint(ParseTailBB);
    
    Value *TailAddr = Builder.CreateCall(StrtoulFunc, {TailToken, ConstantPointerNull::get(CharPtrTy), ConstantInt::get(Int32Ty, 16)});
    
    Value *Size = Builder.CreateSub(TailAddr, HeadAddr);
    
    Builder.CreateBr(CallMprotectBB);
    
    Builder.SetInsertPoint(CallMprotectBB);
    
    FunctionType *AsmFuncTy = FunctionType::get(VoidTy, {Int64Ty, Int64Ty, Int32Ty}, false);
    InlineAsm *MprotectAsm = InlineAsm::get(
        AsmFuncTy,
        "mov x0, $0\n"
        "mov x1, $1\n"
        "mov x2, $2\n"
        "mov x8, #226\n"
        "svc #0",
        "r,r,r", true, false
    );
    
    Value *ProtExec = ConstantInt::get(Int32Ty, 4);
    Builder.CreateCall(MprotectAsm, {HeadAddr, Size, ProtExec});
    
    Builder.CreateBr(NextLineBB);
    
    Builder.SetInsertPoint(NextLineBB);
    Builder.CreateBr(LoopBB);
    
    Builder.SetInsertPoint(CloseAndExitBB);
    
    FunctionCallee FcloseFunc = M.getOrInsertFunction(
        "fclose",
        FunctionType::get(Int32Ty, {CharPtrTy}, false)
    );
    
    Builder.CreateCall(FcloseFunc, {Fp});
    Builder.CreateBr(ExitBB);
    
    Builder.SetInsertPoint(ExitBB);
    Builder.CreateRetVoid();
    
    return Func;
}

bool BanDump::runOnModule(Module &M) {
    if (isIRObfuscationDebugEnabled()) {
        errs() << "[DEBUG] BanDump: Injecting dump protection\n";
    }

    Function *MainFunc = M.getFunction("main");
    if (!MainFunc || MainFunc->isDeclaration()) {
        return false;
    }

    if (MainFunc->empty()) {
        return false;
    }

    BasicBlock &EntryBB = MainFunc->getEntryBlock();
    
    Function *BanDumpFunc = createBanDumpFunc(M);

    IRBuilder<> Builder(&EntryBB, EntryBB.getFirstInsertionPt());
    
    LLVMContext &Ctx = M.getContext();
    
    if (isIRObfuscationDebugEnabled()) {
        FunctionCallee PrintfFunc = M.getOrInsertFunction(
            "printf",
            FunctionType::get(Type::getInt32Ty(Ctx), {PointerType::get(Ctx, 0)}, true)
        );
        Constant *DebugStr = ConstantDataArray::getString(Ctx, "[DEBUG] BanDump: Applying dump protection...\n");
        GlobalVariable *DebugGV = new GlobalVariable(
            M, DebugStr->getType(), true,
            GlobalValue::PrivateLinkage, DebugStr,
            ".bandump.debug"
        );
        Builder.CreateCall(PrintfFunc, {ConstantExpr::getBitCast(DebugGV, PointerType::get(Ctx, 0))});
    }
    
    Builder.CreateCall(BanDumpFunc);

    return true;
}

ModulePass *llvm::createBanDumpPass() {
    return new BanDump();
}

INITIALIZE_PASS_BEGIN(BanDump, "bandump", "Inject dump protection at program start", false, false)
INITIALIZE_PASS_END(BanDump, "bandump", "Inject dump protection at program start", false, false)
