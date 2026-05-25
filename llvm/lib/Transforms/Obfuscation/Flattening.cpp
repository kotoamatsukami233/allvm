//===- Flattening.cpp - 控制流扁平化混淆Pass----------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// 本文件实现控制流扁平化混淆Pass，通过将函数的基本块重组为状态机形式
// 来混淆控制流，增加逆向分析的难度
//
//===----------------------------------------------------------------------===//

#include "llvm/IR/Constants.h"
#include "llvm/Transforms/Obfuscation/Flattening.h"
#include "llvm/Transforms/Obfuscation/ObfuscationPassManager.h"
#include "llvm/Transforms/Obfuscation/LegacyLowerSwitch.h"
#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/CryptoUtils.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/IR/IRBuilder.h"

#include <memory>
#include <random>

#define DEBUG_TYPE "flattening"

using namespace std;
using namespace llvm;

// 统计信息
STATISTIC(Flattened, "已扁平化的函数数量");

namespace {
	struct Flattening : public FunctionPass {
		unsigned    pointerSize;
		static char ID;

		ObfuscationOptions *ArgsOptions;
		CryptoUtils         RandomEngine;

		/**
		 * @brief 构造函数，初始化控制流扁平化Pass
		 * @param pointerSize 指针大小（32位或64位）
		 * @param argsOptions 混淆选项配置对象
		 */
		Flattening(unsigned            pointerSize,
		           ObfuscationOptions *argsOptions) : FunctionPass(ID) {
			this->pointerSize = pointerSize;
			this->ArgsOptions = argsOptions;
		}

		/**
		 * @brief 对单个函数执行控制流扁平化
		 * @param F 要处理的函数
		 * @return 如果函数被修改返回true，否则返回false
		 */
		bool runOnFunction(Function &F) override;
		/**
		 * @brief 执行控制流扁平化的核心逻辑
		 * @param f 要处理的函数指针
		 * @param opt 混淆选项
		 * @return 如果扁平化成功返回true，否则返回false
		 */
		bool flatten(Function *f, const ObfOpt &opt);
	};
}

/**
 * @brief 对单个函数执行控制流扁平化
 * @param F 要处理的函数
 * @return 如果函数被修改返回true，否则返回false
 */
bool Flattening::runOnFunction(Function &F) {
	if (!isLicenseValidated()) return false;

	if (isIRObfuscationDebugEnabled()) {
		errs() << "[DEBUG] Flattening: Starting runOnFunction: " << F.getName() << "\n";
	}
	if (F.isIntrinsic()) {
		return false;
	}
	Function *tmp = &F;
	bool      result = false;
	const auto opt = ArgsOptions->toObfuscate(ArgsOptions->flaOpt(), &F);
	if (!opt.isEnabled()) {
		return result;
	}
	if (flatten(tmp, opt)) {
		++Flattened;
		result = true;
	}

	return result;
}

/**
 * @brief 执行控制流扁平化的核心逻辑
 * @param f 要处理的函数指针
 * @param opt 混淆选项
 * @return 如果扁平化成功返回true，否则返回false
 */
bool Flattening::flatten(Function *f, const ObfOpt &opt) {
	vector<BasicBlock *> origBB;

	auto &Ctx = f->getContext();
	auto  intType = Type::getInt32Ty(Ctx);

	if (pointerSize == 8) {
		intType = Type::getInt64Ty(Ctx);
	}

	char scrambling_key[16];
	cryptoutils->get_bytes(scrambling_key, 16);

	auto lower = std::unique_ptr<FunctionPass>(createLegacyLowerSwitchPass());
	lower->runOnFunction(*f);

	for (auto i = f->begin(); i != f->end(); ++i) {
		auto bb = &*i;
		origBB.push_back(bb);

		if (isa<InvokeInst>(bb->getTerminator()) || bb->isEHPad()) {
			return false;
		}
	}

	if (origBB.size() <= 1) {
		return false;
	}

	origBB.erase(origBB.begin());

	auto insertBlock = &*(f->begin());

	auto splitPos = --(insertBlock->end());

	if (insertBlock->size() > 1) {
		--splitPos;
	}

	std::mt19937_64 re(RandomEngine.get_uint64_t());
	std::shuffle(origBB.begin(), origBB.end(), re);

	auto bbEndOfEntry = insertBlock->splitBasicBlock(splitPos, "first");
	origBB.insert(origBB.begin(), bbEndOfEntry);

	insertBlock->getTerminator()->eraseFromParent();

	IRBuilder<> IRB{insertBlock};
	const auto  switchVar = IRB.CreateAlloca(intType, nullptr, "switchVar");
	const auto  switchXorVar = IRB.CreateAlloca(intType, nullptr, "switchXor");


	ConstantInt *entryRandomXor = cast<ConstantInt>(
	                                  ConstantInt::get(intType, RandomEngine.get_uint64_t()));
	if (pointerSize == 8) {
		auto xorKey = ConstantExpr::getXor(
		                  entryRandomXor,
		                  ConstantInt::get(intType, cryptoutils->scramble64(0, scrambling_key)));

		IRB.CreateStore(xorKey, switchVar, true);
	} else {
		auto xorKey = ConstantExpr::getXor(
		                  entryRandomXor,
		                  ConstantInt::get(intType, cryptoutils->scramble32(0, scrambling_key)));

		IRB.CreateStore(xorKey, switchVar, true);
	}
	IRB.CreateStore(entryRandomXor, switchXorVar, true);

	auto bbLoopEntry = BasicBlock::Create(f->getContext(), "loopEntry", f,
	                                      insertBlock);
	auto bbLoopEnd = BasicBlock::Create(f->getContext(), "loopEnd", f,
	                                    insertBlock);
	IRB.SetInsertPoint(bbLoopEntry);
	auto switchVarLoad = IRB.CreateLoad(intType, switchVar, "switchVar");
	auto switchXorLoad = IRB.CreateLoad(intType, switchXorVar, "switchXor");
	auto switchCondition = IRB.CreateXor(switchVarLoad, switchXorLoad);
	insertBlock->moveBefore(bbLoopEntry);
	BranchInst::Create(bbLoopEntry, insertBlock);

	BranchInst::Create(bbLoopEntry, bbLoopEnd);

	auto swDefault = BasicBlock::Create(f->getContext(), "switchDefault", f,
	                                    bbLoopEnd);
	BranchInst::Create(bbLoopEnd, swDefault);

	auto switchI = SwitchInst::Create(&*f->begin(), swDefault, 0, bbLoopEntry);
	switchI->setCondition(switchCondition);

	f->begin()->getTerminator()->eraseFromParent();

	BranchInst::Create(bbLoopEntry, &*f->begin());

	for (auto bi = origBB.begin(); bi != origBB.end(); ++bi) {
		const auto   bb = *bi;
		ConstantInt *numToCase;
		if (pointerSize == 8) {
			numToCase = cast<ConstantInt>(ConstantInt::get(
			                                  intType,
			                                  cryptoutils->scramble64(switchI->getNumCases(), scrambling_key)));
		} else {
			numToCase = cast<ConstantInt>(ConstantInt::get(
			                                  intType,
			                                  cryptoutils->scramble32(switchI->getNumCases(), scrambling_key)));
		}

		bb->moveBefore(bbLoopEnd);

		switchI->addCase(numToCase, bb);
	}

	for (auto bi = origBB.begin(); bi != origBB.end(); ++bi) {
		const auto bb = *bi;

		if (bb->getTerminator()->getNumSuccessors() == 0) {
			continue;
		}

		IRB.SetInsertPoint(bb->getTerminator());
		if (bb->getTerminator()->getNumSuccessors() == 1) {
			auto tbb = bb->getTerminator()->getSuccessor(0);

			auto numToCase = switchI->findCaseDest(tbb);

			if (numToCase == nullptr) {
				if (pointerSize == 8) {
					numToCase = cast<ConstantInt>(
					                ConstantInt::get(
					                    intType,
					                    cryptoutils->scramble64(0, scrambling_key)));
				} else {
					numToCase = cast<ConstantInt>(
					                ConstantInt::get(
					                    intType,
					                    llvm::cryptoutils->scramble32(0, scrambling_key)));
				}
			}

			ConstantInt *randomXor = cast<ConstantInt>(
			                             ConstantInt::get(intType, RandomEngine.get_uint64_t()));

			auto xorKey = ConstantExpr::getXor(randomXor, numToCase);

			IRB.CreateStore(xorKey, switchVar, true);
			IRB.CreateStore(randomXor, switchXorVar, true);
			IRB.CreateBr(bbLoopEnd);
			bb->getTerminator()->eraseFromParent();
			continue;
		}

		if (bb->getTerminator()->getNumSuccessors() == 2) {
			auto numToCaseTrue =
			    switchI->findCaseDest(bb->getTerminator()->getSuccessor(0));
			auto numToCaseFalse =
			    switchI->findCaseDest(bb->getTerminator()->getSuccessor(1));

			if (numToCaseTrue == nullptr) {
				if (pointerSize == 8) {
					numToCaseTrue = cast<ConstantInt>(
					                    ConstantInt::get(
					                        intType,
					                        llvm::cryptoutils->scramble64(0, scrambling_key)));
				} else {
					numToCaseTrue = cast<ConstantInt>(
					                    ConstantInt::get(
					                        intType,
					                        llvm::cryptoutils->scramble32(0, scrambling_key)));
				}
			}

			if (numToCaseFalse == nullptr) {
				if (pointerSize == 8) {
					numToCaseFalse = cast<ConstantInt>(
					                     ConstantInt::get(
					                         intType,
					                         llvm::cryptoutils->scramble64(0, scrambling_key)));
				} else {
					numToCaseFalse = cast<ConstantInt>(
					                     ConstantInt::get(
					                         intType,
					                         llvm::cryptoutils->scramble32(0, scrambling_key)));
				}
			}

			ConstantInt *randomXor = cast<ConstantInt>(
			                             ConstantInt::get(intType, RandomEngine.get_uint64_t()));

			auto xorKeyT = ConstantExpr::getXor(numToCaseTrue, randomXor);
			auto xorKeyF = ConstantExpr::getXor(numToCaseFalse, randomXor);
			IRB.CreateStore(randomXor, switchXorVar, true);

			auto br = cast<BranchInst>(bb->getTerminator());
			auto sel = IRB.CreateSelect(br->getCondition(), xorKeyT, xorKeyF);

			IRB.CreateStore(sel, switchVar, true);
			IRB.CreateBr(bbLoopEnd);

			bb->getTerminator()->eraseFromParent();
			continue;
		}
	}

	fixStack(f);

	lower->runOnFunction(*f);

	return true;
}

char                            Flattening::ID = 0;
static RegisterPass<Flattening> X("flattening", "Call graph flattening");

/**
 * @brief 创建控制流扁平化Pass
 * @param pointerSize 指针大小（32位或64位）
 * @param argsOptions 混淆选项配置对象
 * @return 返回创建的FunctionPass指针
 */
FunctionPass *llvm::createFlatteningPass(unsigned            pointerSize,
        ObfuscationOptions *argsOptions) {
	return new Flattening(pointerSize, argsOptions);
}
