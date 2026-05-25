//===- RootDetect.cpp - Root检测注入Pass -----------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// 检测到有root权限时退出，打印"你给我滚出去!!!"
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Obfuscation/RootDetect.h"
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

#define DEBUG_TYPE "rootdetect"

using namespace llvm;

namespace {

struct RootDetect : public ModulePass {
    static char ID;

    RootDetect() : ModulePass(ID) {
        initializeRootDetectPass(*PassRegistry::getPassRegistry());
    }

    StringRef getPassName() const override {
        return {"RootDetect"};
    }

    bool runOnModule(Module &M) override;
};

}

char RootDetect::ID = 0;

bool RootDetect::runOnModule(Module &M) {
    if (isIRObfuscationDebugEnabled()) {
        errs() << "[DEBUG] RootDetect: Entering runOnModule\n";
    }

    if (!isLicenseValidated()) {
        if (isIRObfuscationDebugEnabled()) {
            errs() << "[DEBUG] RootDetect: License not validated, exiting\n";
        }
        return false;
    }

    Function *MainFunc = M.getFunction("main");
    if (!MainFunc) {
        if (isIRObfuscationDebugEnabled()) {
            errs() << "[DEBUG] RootDetect: No main function found, exiting\n";
        }
        return false;
    }

    if (isIRObfuscationDebugEnabled()) {
        errs() << "[DEBUG] RootDetect: Found main function: " << MainFunc->getName() << "\n";
    }

    if (MainFunc->isDeclaration()) {
        if (isIRObfuscationDebugEnabled()) {
            errs() << "[DEBUG] RootDetect: main is declaration only, exiting\n";
        }
        return false;
    }

    if (MainFunc->empty()) {
        if (isIRObfuscationDebugEnabled()) {
            errs() << "[DEBUG] RootDetect: main has no body, exiting\n";
        }
        return false;
    }

    LLVMContext &Ctx = M.getContext();
    BasicBlock &EntryBB = MainFunc->getEntryBlock();

    if (isIRObfuscationDebugEnabled()) {
        errs() << "[DEBUG] RootDetect: Splitting entry block...\n";
    }

    BasicBlock *ContinueBB = EntryBB.splitBasicBlock(EntryBB.getFirstInsertionPt(), "root_continue");

    if (isIRObfuscationDebugEnabled()) {
        errs() << "[DEBUG] RootDetect: EntryBB=" << EntryBB.getName()
               << " ContinueBB=" << ContinueBB->getName() << "\n";
    }

    IRBuilder<> Builder(&EntryBB, EntryBB.getFirstInsertionPt());

    Type *Int32Ty = Type::getInt32Ty(Ctx);
    PointerType *CharPtrTy = PointerType::get(Ctx, 0);

    if (isIRObfuscationDebugEnabled()) {
        errs() << "[DEBUG] RootDetect: Declaring external functions...\n";
    }

    FunctionCallee GetuidFunc = M.getOrInsertFunction(
        "getuid",
        FunctionType::get(Int32Ty, {}, false)
    );

    FunctionCallee PrintfFunc = M.getOrInsertFunction(
        "printf",
        FunctionType::get(Int32Ty, {CharPtrTy}, true)
    );

    FunctionCallee FflushFunc = M.getOrInsertFunction(
        "fflush",
        FunctionType::get(Int32Ty, {CharPtrTy}, false)
    );

    FunctionCallee KillFunc = M.getOrInsertFunction(
        "kill",
        FunctionType::get(Int32Ty, {Int32Ty, Int32Ty}, false)
    );

    FunctionCallee GetpidFunc = M.getOrInsertFunction(
        "getpid",
        FunctionType::get(Int32Ty, {}, false)
    );

    if (isIRObfuscationDebugEnabled()) {
        Constant *DebugStr = ConstantDataArray::getString(Ctx, "[DEBUG] RootDetect: Checking root...\n");
        GlobalVariable *DebugGV = new GlobalVariable(
            M, DebugStr->getType(), true,
            GlobalValue::PrivateLinkage, DebugStr,
            ".root.debug"
        );
        Builder.CreateCall(PrintfFunc, {ConstantExpr::getBitCast(DebugGV, CharPtrTy)});
    }

    BasicBlock *CheckBB = BasicBlock::Create(Ctx, "root_check", MainFunc);
    BasicBlock *RootFoundBB = BasicBlock::Create(Ctx, "root_found", MainFunc);

    if (isIRObfuscationDebugEnabled()) {
        errs() << "[DEBUG] RootDetect: Creating BBs: CheckBB=" << CheckBB->getName()
               << " RootFoundBB=" << RootFoundBB->getName() << "\n";
    }

    Builder.CreateBr(CheckBB);
    EntryBB.getTerminator()->eraseFromParent();

    Builder.SetInsertPoint(CheckBB);
    if (isIRObfuscationDebugEnabled()) {
        errs() << "[DEBUG] RootDetect: Building getuid() check in CheckBB\n";
    }
    Value *Uid = Builder.CreateCall(GetuidFunc);
    Value *IsRoot = Builder.CreateICmpEQ(Uid, ConstantInt::get(Int32Ty, 0));
    Builder.CreateCondBr(IsRoot, RootFoundBB, ContinueBB);

    Builder.SetInsertPoint(RootFoundBB);
    if (isIRObfuscationDebugEnabled()) {
        errs() << "[DEBUG] RootDetect: Building root-found exit in RootFoundBB\n";
    }
    Constant *MsgStr = ConstantDataArray::getString(Ctx, "你给我滚出去!!!\n");
    GlobalVariable *MsgGV = new GlobalVariable(
        M, MsgStr->getType(), true,
        GlobalValue::PrivateLinkage, MsgStr,
        ".root.msg"
    );
    Builder.CreateCall(PrintfFunc, {ConstantExpr::getBitCast(MsgGV, CharPtrTy)});
    Builder.CreateCall(FflushFunc, {ConstantPointerNull::get(CharPtrTy)});

    Value *Pid = Builder.CreateCall(GetpidFunc);
    Builder.CreateCall(KillFunc, {Pid, ConstantInt::get(Int32Ty, 9)});
    Builder.CreateUnreachable();

    if (isIRObfuscationDebugEnabled()) {
        errs() << "[DEBUG] RootDetect: Insertion complete, returning true\n";
    }

    return true;
}

ModulePass *llvm::createRootDetectPass() {
    return new RootDetect();
}

INITIALIZE_PASS_BEGIN(RootDetect, "rootdetect", "Inject root detection at main", false, false)
INITIALIZE_PASS_END(RootDetect, "rootdetect", "Inject root detection at main", false, false)
